from __future__ import annotations

"""模型适配层。

职责：
- 把 snapshot/evidence 打包成 prompt 发给本地模型（Ollama）
- 解析模型返回的 JSON
- 做结果纠偏（coerce），保证结构可用于后续阶段
"""

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from .logger import get_logger, current_request_id, current_task_id

logger = get_logger("model")


class ModelAdapter:
    """统一封装模型调用与输出清洗逻辑。"""

    _MANUAL_SKIP_PREFIX = "NO_"

    def __init__(
        self,
        provider: str,
        model_name: str,
        *,
        project_root: Path,
        base_url: str = "http://127.0.0.1:11434",
        temperature: float = 0.1,
        timeout_sec: int = 120,
        max_retries: int = 1,
        progress_callback=None,
        snapshot_limits: Dict[str, int] | None = None,
        evidence_limits: Dict[str, int] | None = None,
        round1_limits: Dict[str, int] | None = None,
        specific_options: Dict[str, Dict[str, Any]] | None = None,
    ):
        self.provider = provider
        self.model_name = model_name
        self.project_root = project_root
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.timeout_sec = timeout_sec
        self.max_retries = max(0, int(max_retries))
        self.progress_callback = progress_callback
        self.snapshot_limits = snapshot_limits or {
            "functions": 80,
            "strings": 80,
            "imports": 80,
            "dangerous_calls": 24,
        }
        self.evidence_limits = evidence_limits or {
            "evidence_items": 12,
            "items_preview": 8,
            "text_chars": 1200,
        }
        self.round1_limits = round1_limits or {
            "batch_size": 3,
            "max_batches": 6,
            "max_requests": 8,
            "priority_top_n": 48,
        }
        # 兼容旧配置：若缺失新增字段则补默认值。
        self.round1_limits.setdefault("priority_top_n", 48)

        self.specific_options = specific_options or {}
        self.knowledge_base = self._load_local_knowledge_base()
        self.last_raw_output: str = ""
        self.last_repair_output: str = ""

    def _notify(self, payload: Dict[str, Any]) -> None:
        """向前端回传模型子阶段进度。"""
        if not self.progress_callback:
            return
        try:
            data = dict(payload)
            data.setdefault("event", "model_progress")
            data.setdefault("request_id", current_request_id())
            data.setdefault("task_id", current_task_id())
            self.progress_callback(data)
        except Exception:
            pass

    def analyze_round1(self, snapshot: Dict[str, Any], *, model_name: str | None = None) -> Dict[str, Any]:
        """首轮分析（模型输出 Markdown 模板，宿主解析为结构化字典）。"""
        if self.provider == "ollama":
            prompt_tpl = self._read_prompt("prompts/round1_prompt.txt")
            merged: Dict[str, Any] | None = None
            batches = self._build_round1_batches(snapshot)[: self.round1_limits["max_batches"]]
            logger.info("round1 start: model=%s batches=%d", model_name or self.model_name, len(batches))
            self._notify({"phase": "round1", "action": "start", "model": model_name or self.model_name, "batches": len(batches)})
            for idx, batch in enumerate(batches, start=1):
                self._notify({"phase": "round1", "action": "batch_start", "index": idx, "total": len(batches)})
                compact_snapshot = self._compact_snapshot(batch)
                prompt = (
                    prompt_tpl
                    .replace("{{SNAPSHOT_JSON}}", json.dumps(compact_snapshot, ensure_ascii=False, indent=2))
                    .replace("{{KNOWLEDGE_BASE}}", self._render_knowledge_base_context(compact_snapshot, phase="round1"))
                )
                md = self._ollama_generate(prompt, model_name=model_name, force_json=False)
                self.last_raw_output = md
                parsed = self._parse_round1_markdown(md)
                merged = self._merge_round1_results(merged, parsed)
                logger.info("round1 batch done: %d/%d", idx, len(batches))
                self._notify({"phase": "round1", "action": "batch_done", "index": idx, "total": len(batches)})

            if merged:
                result = self._finalize_round1_result(merged, snapshot)
                result = self._sanitize_round1_result(result, snapshot)
                logger.info(
                    "round1 done: order=%d suspects=%d requests=%d",
                    len(result.get("analysis_order", [])),
                    len(result.get("suspicious_functions", [])),
                    len(result.get("next_evidence_requests", [])),
                )
                self._notify({"phase": "round1", "action": "done"})
                return result
            raise RuntimeError("round1 未获得有效模型输出")
        raise ValueError(f"Unsupported model provider: {self.provider}")

    def analyze_final(self, evidence_bundle: Dict[str, Any], *, model_name: str | None = None) -> Dict[str, Any]:
        """最终分析。严格 fail-fast，不做修复、猜测或透传。"""
        if self.provider == "ollama":
            logger.info("final start: model=%s", model_name or self.model_name)
            self._notify({"phase": "final", "action": "start", "model": model_name or self.model_name})
            prompt_tpl = self._read_prompt("prompts/final_prompt.txt")
            compact_bundle = self._compact_evidence_bundle(evidence_bundle)
            prompt = (
                prompt_tpl
                .replace("{{EVIDENCE_JSON}}", json.dumps(compact_bundle, ensure_ascii=False, indent=2))
                .replace("{{KNOWLEDGE_BASE}}", self._render_knowledge_base_context(compact_bundle, phase="final"))
            )
            prompt = f"{prompt}\n\n{self._final_focus_hint(compact_bundle)}"
            self._notify({"phase": "final", "action": "generate_initial"})
            md = self._ollama_generate(prompt, model_name=model_name, force_json=False)
            self.last_raw_output = md
            parsed = self._parse_final_markdown(md)
            parsed = self._sanitize_final_report(parsed, compact_bundle)
            parsed["vulnerability_locations"] = self._derive_vulnerability_locations(parsed, compact_bundle)
            self._ensure_final_semantic_minimum(parsed, compact_bundle)
            logger.info("final parsed structured output")
            self._notify({"phase": "final", "action": "initial_success"})
            return parsed
        raise ValueError(f"Unsupported model provider: {self.provider}")

    def _read_prompt(self, rel: str) -> str:
        """读取 prompt 模板。"""
        return (self.project_root / rel).read_text(encoding="utf-8")

    def _load_local_knowledge_base(self) -> Dict[str, Any]:
        """加载本地漏洞知识库；缺失时返回空结构，不中断主流程。"""
        path = self.project_root / "knowledge" / "vuln_patterns.json"
        if not path.exists():
            logger.warning("local knowledge base not found: %s", path)
            return {"version": 0, "entries": []}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("failed to load local knowledge base: %s", exc)
            return {"version": 0, "entries": []}

        entries = data.get("entries", [])
        if not isinstance(entries, list):
            logger.warning("local knowledge base has invalid entries field")
            return {"version": int(data.get("version", 0) or 0), "entries": []}
        return {
            "version": int(data.get("version", 0) or 0),
            "entries": [item for item in entries if isinstance(item, dict)],
        }

    def _context_text_from_payload(self, payload: Dict[str, Any]) -> str:
        """把 snapshot/evidence bundle 压平成文本，供知识库模式做轻量匹配。"""
        chunks: List[str] = []

        def _walk(value: Any) -> None:
            if isinstance(value, dict):
                for item in value.values():
                    _walk(item)
                return
            if isinstance(value, list):
                for item in value:
                    _walk(item)
                return
            if isinstance(value, str):
                text = value.strip()
                if text:
                    chunks.append(text.lower())

        _walk(payload)
        return "\n".join(chunks)

    def _score_knowledge_entry(self, entry: Dict[str, Any], context_text: str, phase: str) -> int:
        """按上下文为知识条目打分，优先输出更相关的漏洞模式。"""
        score = 0
        for token in entry.get("aliases", []) if isinstance(entry.get("aliases"), list) else []:
            alias = str(token).strip().lower()
            if alias and alias in context_text:
                score += 5
        for token in entry.get("trigger_signals", []) if isinstance(entry.get("trigger_signals"), list) else []:
            phrase = str(token).strip().lower()
            if not phrase:
                continue
            for unit in re.split(r"[、/，,；; ]+", phrase):
                clean = unit.strip()
                if clean and clean in context_text:
                    score += 1

        name = str(entry.get("name_cn", "")).strip()
        if phase == "final" and name == "释放后使用":
            for token in ["free", "rm", "delete", "view", "show", "edit", "modify", "dangling", "printf"]:
                if token in context_text:
                    score += 2
        if phase == "final" and name == "堆溢出":
            for token in ["malloc", "calloc", "memcpy", "read", "recv", "chunk", "size"]:
                if token in context_text:
                    score += 1
        return score

    def _select_knowledge_entries(self, payload: Dict[str, Any], phase: str) -> List[Dict[str, Any]]:
        """选出当前最相关的知识条目；若匹配不足则返回全部高频条目。"""
        entries = self.knowledge_base.get("entries", []) if isinstance(self.knowledge_base, dict) else []
        if not isinstance(entries, list) or not entries:
            return []

        context_text = self._context_text_from_payload(payload)
        scored = []
        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            scored.append((self._score_knowledge_entry(entry, context_text, phase), idx, entry))

        scored.sort(key=lambda item: (-item[0], item[1]))
        selected = [entry for score, _, entry in scored if score > 0][:5]
        if selected:
            return selected
        return [entry for _, _, entry in scored[:5]]

    def _render_knowledge_base_context(self, payload: Dict[str, Any], *, phase: str) -> str:
        """把本地知识库渲染成简洁提示文本，供模型参考。"""
        entries = self._select_knowledge_entries(payload, phase)
        if not entries:
            return "（未加载到本地知识库）"

        lines = [
            f"知识库版本: {self.knowledge_base.get('version', 0)}",
            "使用原则:",
            "- 知识库只提供高频漏洞判别框架，不能替代当前样本证据。",
            "- 只有同时满足关键观察点时，才能输出对应漏洞结论。",
            "- 看到危险 API 名称时，先排除误判陷阱，再下结论。",
        ]
        for entry in entries:
            name = str(entry.get("name_cn", "")).strip() or str(entry.get("id", "")).strip()
            signals = [
                str(item).strip()
                for item in entry.get("trigger_signals", [])[:2]
                if str(item).strip()
            ] if isinstance(entry.get("trigger_signals"), list) else []
            observations = [
                str(item).strip()
                for item in entry.get("key_observations", [])[:2]
                if str(item).strip()
            ] if isinstance(entry.get("key_observations"), list) else []
            traps = [
                str(item).strip()
                for item in entry.get("false_positive_traps", [])[:1]
                if str(item).strip()
            ] if isinstance(entry.get("false_positive_traps"), list) else []
            lines.append(f"- {name}")
            if signals:
                lines.append(f"  触发信号: {'；'.join(signals)}")
            if observations:
                lines.append(f"  关键观察: {'；'.join(observations)}")
            if traps:
                lines.append(f"  误判陷阱: {'；'.join(traps)}")
        return "\n".join(lines)

    def _section(self, text: str, title: str) -> str:
        """提取指定标题下的内容，支持多种变体和模糊匹配。"""
        # 生成可能的标题变体
        title_variants = [title]
        if " " in title:
            # 对于多单词标题，尝试移除空格和下划线变体
            title_variants.append(title.replace(" ", ""))
            title_variants.append(title.replace(" ", "_"))
            title_variants.append(title.replace(" ", "-"))
        
        # 尝试匹配每个变体
        for variant in title_variants:
            # 精确匹配变体
            pat = re.compile(rf"^#+\s*{re.escape(variant)}\s*$", re.IGNORECASE | re.MULTILINE)
            m = pat.search(text)
            if m:
                return self._extract_section_content(text, m)
            
            # 模糊匹配：标题包含变体作为子串
            # 匹配 "## Some Title with Vulnerability Type in it" 这样的情况
            pat_fuzzy = re.compile(rf"^#+\s*(.*?{re.escape(variant)}.*?)\s*$", re.IGNORECASE | re.MULTILINE)
            m_fuzzy = pat_fuzzy.search(text)
            if m_fuzzy:
                return self._extract_section_content(text, m_fuzzy)
        
        # 如果没有找到匹配的标题，返回空字符串
        return ""
    
    def _extract_section_content(self, text: str, match) -> str:
        """从匹配位置提取节内容直到下一个标题或文件结束。"""
        start = match.end()
        rest = text[start:]
        
        # 查找下一个标题行
        next_title = re.search(r"^#+.+$", rest, re.MULTILINE)
        if next_title:
            content = rest[:next_title.start()].strip()
        else:
            content = rest.strip()
        
        return content

    def _parse_list(self, block: str) -> list[str]:
        out = []
        for ln in block.splitlines():
            s = ln.strip()
            if not s:
                continue
            s = re.sub(r"^[-*]\s*", "", s)
            if s:
                out.append(s)
        return out

    def _parse_round1_markdown(self, md: str) -> Dict[str, Any]:
        order = self._parse_list(self._section(md, "Analysis Order"))
        suspects_raw = self._parse_list(self._section(md, "Suspicious Functions"))
        hypotheses = self._parse_list(self._section(md, "Hypotheses"))
        gaps = self._parse_list(self._section(md, "Evidence Gaps"))
        reqs_raw = self._parse_list(self._section(md, "Next Evidence Requests"))

        if not order:
            raise RuntimeError("round1 markdown missing section: Analysis Order")
        if hypotheses is None or not hypotheses:
            raise RuntimeError("round1 markdown missing section: Hypotheses")
        if gaps is None or not gaps:
            raise RuntimeError("round1 markdown missing section: Evidence Gaps")

        suspects = []
        for s in suspects_raw:
            name, _, reason = s.partition(":")
            name = name.strip().strip("`")
            reason = (reason or "可疑").strip()
            if name:
                suspects.append({"name": name, "reason": reason})

        reqs = []
        for s in reqs_raw:
            m = re.match(r"-?\s*(get_callers|get_callees|get_pseudocode)\s*:\s*(\S+)", s)
            if m:
                reqs.append({"tool": m.group(1), "target": m.group(2).strip("`")})

        hypotheses = [self._to_zh_text(x) for x in hypotheses]
        gaps = [self._to_zh_text(x) for x in gaps]
        for item in suspects:
            item["reason"] = self._to_zh_text(str(item.get("reason", "")))

        return {
            "analysis_order": order,
            "function_summaries": [],
            "semantic_renames": [],
            "suspicious_functions": suspects,
            "hypotheses": hypotheses,
            "evidence_gaps": gaps,
            "next_evidence_requests": reqs,
        }

    def _parse_final_markdown(self, md: str) -> Dict[str, Any]:
        suspicious_site = (
            self._section(md, "Primary Suspicious Site") or
            self._section(md, "最可疑位置") or
            self._section(md, "Primary Site")
        )
        vuln_type = (
            self._section(md, "Vulnerability Type") or
            self._section(md, "漏洞类型") or
            self._section(md, "Vulnerability") or
            self._section(md, "漏洞") or
            self._section(md, "Vuln Type") or
            self._section(md, "Vuln")
        )
        
        # 增强函数列表提取
        funcs = (
            self._parse_list(self._section(md, "Vulnerable Functions")) or
            self._parse_list(self._section(md, "可疑函数")) or
            self._parse_list(self._section(md, "Vulnerable")) or
            self._parse_list(self._section(md, "可疑"))
        )
        
        root = (
            self._section(md, "Root Cause") or
            self._section(md, "根因") or
            self._section(md, "Root") or
            self._section(md, "原因")
        )
        
        trig = (
            self._section(md, "Trigger Condition") or
            self._section(md, "触发条件") or
            self._section(md, "Trigger") or
            self._section(md, "触发")
        )
        
        evid = (
            self._parse_list(self._section(md, "Key Evidence")) or
            self._parse_list(self._section(md, "关键证据")) or
            self._parse_list(self._section(md, "Evidence")) or
            self._parse_list(self._section(md, "证据"))
        )
        
        impact = (
            self._section(md, "Impact") or
            self._section(md, "影响") or
            self._section(md, "后果")
        )
        risk = (
            self._section(md, "False Positive Risk") or
            self._section(md, "误报风险") or
            self._section(md, "Risk")
        )
        
        patch = (
            self._section(md, "Patch Idea") or
            self._section(md, "修复思路") or
            self._section(md, "Patch") or
            self._section(md, "修复建议") or
            self._section(md, "修复")
        )
        
        fix = (
            self._section(md, "Minimal Fix") or
            self._section(md, "最小修复") or
            self._section(md, "Minimal Repair") or
            self._section(md, "修复方案")
        )
        
        checks = (
            self._parse_list(self._section(md, "Manual Checks")) or
            self._parse_list(self._section(md, "人工复核")) or
            self._parse_list(self._section(md, "Manual")) or
            self._parse_list(self._section(md, "人工检查"))
        )

        required_sections = {
            "Primary Suspicious Site": suspicious_site,
            "Vulnerability Type": vuln_type,
            "Vulnerable Functions": funcs,
            "Root Cause": root,
            "Trigger Condition": trig,
            "Key Evidence": evid,
            "Impact": impact,
            "False Positive Risk": risk,
            "Patch Idea": patch,
            "Minimal Fix": fix,
            "Manual Checks": checks,
        }
        missing = [name for name, value in required_sections.items() if not value]
        if missing:
            raise RuntimeError("final markdown missing required sections: " + ", ".join(missing))

        risk_text = str(risk).strip().lower()
        if risk_text not in {"low", "medium", "high"}:
            raise RuntimeError(f"final markdown has invalid False Positive Risk: {risk!r}")

        out = {
            "primary_suspicious_site": self._to_zh_text(suspicious_site.strip()),
            "suspected_vulnerability_type": self._to_zh_text(self._normalize_final_text(vuln_type)),
            "vulnerable_functions": self._normalize_function_names(funcs),
            "root_cause": self._to_zh_text(root.strip()),
            "trigger_condition": self._to_zh_text(trig.strip()),
            "key_evidence": [self._to_zh_text(x) for x in evid],
            "impact": self._to_zh_text(impact.strip()),
            "false_positive_risk": risk_text,
            "patch_idea": self._to_zh_text(patch.strip()),
            "minimal_fix": self._to_zh_text(fix.strip()),
            "manual_checks": [self._to_zh_text(x) for x in checks],
        }
        if not out["vulnerable_functions"]:
            raise RuntimeError("final markdown has empty Vulnerable Functions")
        return out

    def _infer_functions_from_content(self, text: str) -> list[str]:
        """从自由文本中提取被明确讨论的函数名。"""
        out: list[str] = []
        seen: set[str] = set()
        patterns = [
            r"[`“\"]([A-Za-z_][A-Za-z0-9_]*)[`”\"]\s*函数",
            r"在[`“\"]?([A-Za-z_][A-Za-z0-9_]*)[`”\"]?函数中",
            r"\*\*`?([A-Za-z_][A-Za-z0-9_]*)`?\s*函数\*\*",
        ]
        for pat in patterns:
            for name in re.findall(pat, text):
                if name not in seen:
                    seen.add(name)
                    out.append(name)
        return out

    def _infer_root_cause_from_content(self, text: str) -> str:
        """从自由文本中提取最可能的根因句。"""
        sentences = re.split(r"(?<=[。！？.!?])\s+|\n+", text)
        keywords = [
            "未检查",
            "没有检查",
            "缺少",
            "缺乏",
            "未验证",
            "输入验证",
            "边界检查",
            "长度检查",
            "没有被限制长度",
            "未显示对内容长度的检查",
            "超过实际分配",
            "use-after-free",
            "释放后使用",
        ]
        for para in sentences:
            s = para.strip(" -\t")
            if not s:
                continue
            if any(key in s for key in keywords):
                return s
        return ""

    def _infer_trigger_from_content(self, text: str) -> str:
        """从自由文本中提取触发条件。"""
        for para in text.splitlines():
            s = para.strip(" -\t")
            if not s:
                continue
            if any(key in s for key in ["攻击者可以", "通过输入", "如果用户", "当用户", "输入", "触发"]):
                return s
        return ""

    def _infer_evidence_list_from_content(self, text: str) -> list[str]:
        """从自由文本中抽取带函数名/API 的证据句。"""
        out: list[str] = []
        for para in text.splitlines():
            s = para.strip(" -\t")
            if not s:
                continue
            if len(s) < 12:
                continue
            if any(ch in s for ch in ["`", "NO_", "add", "fill", "Free", "dump", "main", "read", "calloc", "free"]):
                out.append(s)
            if len(out) >= 4:
                break
        return out

    def _infer_impact_from_content(self, text: str) -> str:
        """从自由文本中提取影响描述。"""
        sentences = re.split(r"(?<=[。！？.!?])\s+|\n+", text)
        impact_keywords = [
            "任意代码执行",
            "崩溃",
            "拒绝服务",
            "数据损坏",
            "代码执行",
            "安全风险",
            "安全漏洞",
            "缓冲区溢出",
            "堆溢出",
            "栈溢出",
            "内存破坏",
            "信息泄露",
            "控制流劫持",
        ]
        for s in sentences:
            clean = s.strip(" -\t")
            if any(key in clean for key in impact_keywords):
                return clean
        for para in text.splitlines():
            s = para.strip(" -\t")
            if any(key in s for key in impact_keywords):
                return s
        return ""

    def _infer_patch_from_content(self, text: str) -> str:
        """从自由文本中提取修复思路。"""
        for para in text.splitlines():
            s = para.strip(" -*\t")
            if not s:
                continue
            if s.startswith("建议修复措施"):
                continue
            if any(key in s for key in ["添加输入验证", "检查索引范围", "边界", "保护机制", "确保", "限制用户输入", "验证输入"]):
                return s
        return ""

    def _infer_fix_from_content(self, text: str) -> str:
        """从自由文本中提取最小修复动作。"""
        for para in text.splitlines():
            s = para.strip(" -*\t")
            if not s:
                continue
            if any(key in s for key in ["检查索引范围", "输入验证", "比较", "限制", "拒绝", "边界检查", "不超过预分配", "截断", "小于等于15"]):
                return s
        return ""

    def _infer_checks_from_content(self, text: str) -> list[str]:
        """从自由文本中提取人工复核项。"""
        out: list[str] = []
        for para in text.splitlines():
            s = para.strip(" -\t")
            if any(key in s for key in ["建议获取", "获取", "重新分析", "更多证据", "伪代码"]):
                out.append(s)
            if len(out) >= 3:
                break
        return out

    def _normalize_final_text(self, text: str) -> str:
        """清洗最终字段，避免整张表或大段说明落入单个字符串字段。"""
        cleaned = str(text or "").strip()
        if not cleaned:
            return ""

        wrapped = re.match(
            r'^"?[A-Za-z_][A-Za-z0-9_]*"?\s*:\s*"?(.*?)"?\s*,?\s*$',
            cleaned,
            flags=re.DOTALL,
        )
        if wrapped:
            cleaned = wrapped.group(1).strip()

        lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
        if any(ln.startswith("|") for ln in lines):
            for ln in lines:
                if "漏洞类型" in ln and "|" in ln:
                    cells = [c.strip(" *`") for c in ln.split("|") if c.strip()]
                    if len(cells) >= 2:
                        return cells[-1]
        for ln in lines:
            if ln.startswith(">"):
                continue
            if ln.startswith("- "):
                return ln[2:].strip()
            if not ln.startswith("|"):
                return ln
        return cleaned

    def _normalize_function_names(self, names: list[str]) -> list[str]:
        """清洗函数名列表，去掉多余 markdown 包裹和非函数描述。"""
        out: list[str] = []
        seen: set[str] = set()
        for item in names:
            name = str(item or "").strip().strip("`").strip()
            if not name:
                continue
            if "|" in name:
                cells = [c.strip(" *`") for c in name.split("|") if c.strip()]
                for cell in reversed(cells):
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cell):
                        name = cell
                        break
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                continue
            if name not in seen:
                seen.add(name)
                out.append(name)
        return out

    def _extract_function_names_from_text(self, text: str) -> list[str]:
        """从自由格式最终输出中补提取函数名。"""
        patterns = [
            r"关键函数[^`\n]*`([A-Za-z_][A-Za-z0-9_]*)`",
            r"漏洞函数[^`\n]*`([A-Za-z_][A-Za-z0-9_]*)`",
            r"Vulnerable Functions[\s\S]*?`([A-Za-z_][A-Za-z0-9_]*)`",
        ]
        out: list[str] = []
        seen: set[str] = set()
        for pat in patterns:
            for name in re.findall(pat, text, flags=re.IGNORECASE):
                if name not in seen:
                    seen.add(name)
                    out.append(name)
        return out

    def _extract_vuln_type_from_text(self, text: str) -> str:
        """从自由格式文本中提取漏洞类型描述。"""
        # 尝试查找包含漏洞类型的关键段落
        lines = text.splitlines()
        for line in lines:
            line_lower = line.lower()
            # 寻找包含漏洞关键词的行
            vuln_keywords = ["buffer overflow", "heap overflow", "stack overflow", "use after free", 
                           "double free", "format string", "integer overflow", "race condition",
                           "command injection", "sql injection", "xss", "csrf", "arbitrary code execution",
                           "内存破坏", "堆溢出", "栈溢出", "释放后使用", "双重释放", "格式化字符串",
                           "整数溢出", "竞争条件", "命令注入", "sql注入", "跨站脚本", "跨站请求伪造", "任意代码执行"]
            
            for keyword in vuln_keywords:
                if keyword in line_lower:
                    # 提取整行作为漏洞类型描述
                    clean_line = line.strip()
                    if len(clean_line) > 200:
                        clean_line = clean_line[:200] + "..."
                    return clean_line
        
        # 如果没有找到明确的关键词，返回空字符串
        return ""

    def _infer_vuln_type_from_content(self, text: str) -> str:
        """从内容中推断漏洞类型（基于常见模式）。"""
        text_lower = text.lower()
        
        # 检查常见漏洞模式
        if any(x in text_lower for x in ["buffer overflow", "缓冲区溢出", "栈溢出", "stack overflow"]):
            return "缓冲区溢出"
        elif any(x in text_lower for x in ["heap overflow", "堆溢出", "use after free", "释放后使用"]):
            return "堆内存破坏"
        elif any(x in text_lower for x in ["format string", "格式化字符串"]):
            return "格式化字符串漏洞"
        elif any(x in text_lower for x in ["integer overflow", "整数溢出"]):
            return "整数溢出"
        elif any(x in text_lower for x in ["command injection", "命令注入", "system(", "exec("]):
            return "命令注入"
        elif any(x in text_lower for x in ["arbitrary code execution", "任意代码执行"]):
            return "任意代码执行"
        elif any(x in text_lower for x in ["race condition", "竞争条件"]):
            return "竞争条件"
        elif any(x in text_lower for x in ["double free", "双重释放"]):
            return "双重释放漏洞"
        
        # 默认返回通用类型
        return "疑似内存破坏漏洞"

    def dump_last_raw_outputs(self, out_dir: Path, phase: str) -> None:
        """落盘最近一次模型原始输出，便于定位 schema 失败原因。"""
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.last_raw_output:
            (out_dir / f"{phase}_model_raw.txt").write_text(self.last_raw_output, encoding="utf-8")
        if self.last_repair_output:
            (out_dir / f"{phase}_model_repair.txt").write_text(self.last_repair_output, encoding="utf-8")

    def _ollama_generate(self, prompt: str, *, model_name: str | None = None, force_json: bool = False) -> str:
        """调用 Ollama /api/generate（非流式）。支持特定模型的选项配置。"""
        target_model = model_name or self.model_name
        url = f"{self.base_url}/api/generate"

        # 基础选项
        options = {"temperature": self.temperature}
        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }

        # 检查是否有特定模型的选项配置
        if target_model in self.specific_options:
            model_options = self.specific_options[target_model]
            # Ollama 的 think 属于顶级请求字段，不能塞进 options。
            for key, value in model_options.items():
                if key in {"think"}:
                    payload[key] = value
                    continue
                if key not in ["model", "prompt", "stream", "format"]:
                    options[key] = value

        if force_json:
            payload["format"] = "json"

        logger.debug(
            "ollama request: model=%s think=%s options=%s",
            target_model,
            payload.get("think"),
            options,
        )
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Ollama request failed: {e}") from e

        try:
            result = json.loads(body)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Ollama returned non-JSON response: {body[:300]}") from e

        text = result.get("response")
        if not isinstance(text, str):
            raise RuntimeError(f"Ollama response missing text field: {result}")
        return text

    def _generate_json(self, prompt: str, *, model_name: str | None = None) -> Dict[str, Any]:
        """直接要求模型输出 JSON（保留给调试/兼容场景）。"""
        last_error: Exception | None = None
        self.last_raw_output = ""
        self.last_repair_output = ""

        for attempt in range(self.max_retries + 1):
            raw = self._ollama_generate(prompt, model_name=model_name, force_json=True)
            self.last_raw_output = raw
            try:
                obj = self._parse_json_object(raw)
                self._reject_wrapped_object(obj)
                return obj
            except RuntimeError as e:
                last_error = e

            if attempt >= self.max_retries:
                break

        raise RuntimeError(f"Model output is not valid JSON object after retries: {last_error}")

    def _generate_from_yaml_prompt(self, prompt: str, *, model_name: str | None = None) -> Dict[str, Any]:
        """模型先输出 YAML，再转换为 JSON（宿主层结构约束）。"""
        last_error: Exception | None = None
        self.last_raw_output = ""
        self.last_repair_output = ""

        for attempt in range(self.max_retries + 1):
            yaml_text = self._ollama_generate(prompt, model_name=model_name, force_json=False)
            self.last_raw_output = yaml_text

            convert_prompt = (
                "将下面 YAML 严格转换为一个 JSON 对象。\n"
                "要求：\n"
                "1) 只输出 JSON 对象本身。\n"
                "2) 不新增字段，不删除字段，不改字段名。\n"
                "3) 不输出 markdown，不输出解释。\n"
                "YAML 输入:\n"
                f"{yaml_text[:20000]}"
            )
            json_text = self._ollama_generate(convert_prompt, model_name=model_name, force_json=True)
            self.last_repair_output = json_text

            try:
                obj = self._parse_json_object(json_text)
                self._reject_wrapped_object(obj)
                return obj
            except RuntimeError as e:
                last_error = e

            if attempt >= self.max_retries:
                break

        raise RuntimeError(f"YAML->JSON conversion failed after retries: {last_error}")

    def _reject_wrapped_object(self, obj: Dict[str, Any]) -> None:
        """拒绝常见错误包裹层输出（如 round3/analysis/result）。"""
        if len(obj) != 1:
            return
        key = str(next(iter(obj.keys()), "")).strip().lower()
        if re.match(r"^round\d+$", key) or key in {"analysis", "result", "data", "conclusion", "output"}:
            raise RuntimeError(f"Model output uses forbidden wrapper key: {key}")

    def _parse_json_object(self, text: str) -> Dict[str, Any]:
        """从模型输出中提取 JSON 对象。

        兼容：
        - fenced code block
        - 前后夹杂解释文本
        """
        candidate = text.strip()

        if candidate.startswith("```"):
            lines = [ln for ln in candidate.splitlines() if not ln.strip().startswith("```")]
            candidate = "\n".join(lines).strip()

        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

        extracted = self._extract_first_json_object(candidate)
        if extracted is not None:
            try:
                obj = json.loads(extracted)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass

        start = candidate.find("{")
        end = candidate.rfind("}")
        if start != -1 and end != -1 and end > start:
            chunk = candidate[start : end + 1]
            try:
                obj = json.loads(chunk)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass

        raise RuntimeError("Model output is not valid JSON object")

    def _extract_first_json_object(self, text: str) -> str | None:
        """从混杂文本中提取第一个括号平衡的 JSON 对象。"""
        start = text.find("{")
        if start == -1:
            return None

        depth = 0
        in_string = False
        escaped = False
        for idx in range(start, len(text)):
            ch = text[idx]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : idx + 1]
        return None

    def _repair_json_output(self, raw: str, *, model_name: str | None = None) -> str | None:
        raise RuntimeError("JSON repair 已禁用；请直接返回合法 JSON")

    def _repair_final_markdown(
        self,
        raw: str,
        compact_bundle: Dict[str, Any],
        *,
        model_name: str | None = None,
    ) -> str:
        raise RuntimeError("final markdown repair 已禁用；模型输出无效时应直接失败")

    def _final_focus_hint(self, compact_bundle: Dict[str, Any]) -> str:
        """给 final 模型明确的函数/API 白名单与输出关注点。"""
        round1 = compact_bundle.get("round1", {}) if isinstance(compact_bundle.get("round1"), dict) else {}
        snapshot = compact_bundle.get("snapshot", {}) if isinstance(compact_bundle.get("snapshot"), dict) else {}
        round2 = compact_bundle.get("round2", {}) if isinstance(compact_bundle.get("round2"), dict) else {}

        funcs: list[str] = []
        for name in round1.get("analysis_order", []) if isinstance(round1.get("analysis_order"), list) else []:
            clean = str(name).strip()
            if clean and clean not in funcs:
                funcs.append(clean)
        apis: list[str] = []
        for item in snapshot.get("dangerous_calls", []) if isinstance(snapshot.get("dangerous_calls"), list) else []:
            if not isinstance(item, dict):
                continue
            api = str(item.get("api", "")).strip()
            if api and api not in apis:
                apis.append(api)
        pseudocode_targets: list[str] = []
        for item in round2.get("evidence_items", []) if isinstance(round2.get("evidence_items"), list) else []:
            if not isinstance(item, dict):
                continue
            req = item.get("request", {}) if isinstance(item.get("request"), dict) else {}
            if str(req.get("tool", "")).strip() != "get_pseudocode":
                continue
            target = str(req.get("target", "")).strip()
            if target and target not in pseudocode_targets:
                pseudocode_targets.append(target)

        return (
            "严格约束：\n"
            f"- 你只能在这些函数名中选择和引用：{', '.join(funcs) if funcs else '无'}\n"
            f"- 你只能围绕这些已知危险 API / 关键调用作答：{', '.join(apis) if apis else '无'}\n"
            f"- 当前拿到伪代码的重点函数：{', '.join(pseudocode_targets) if pseudocode_targets else '无'}\n"
            "- 先指出最异常的一行/一个调用点，再给出漏洞归因；不要先套固定漏洞模板。\n"
            "- 不要编造证据包中不存在的函数名，例如 `write`、`vuln`、`buf`、`len` 对应的业务函数。\n"
            "- 如果某个 helper 带有 `NO_` 前缀，它表示人工标记的低优先级辅助函数；优先归因到调用它的上层业务函数。\n"
        )

    def _ensure_final_semantic_minimum(self, report: Dict[str, Any], compact_bundle: Dict[str, Any]) -> None:
        """在进入 workflow 严格校验前，先拦截明显离题或空洞的 final 输出。"""
        vuln_type = str(report.get("suspected_vulnerability_type", "")).strip()
        suspicious_site = str(report.get("primary_suspicious_site", "")).strip()
        root = str(report.get("root_cause", "")).strip()
        trigger = str(report.get("trigger_condition", "")).strip()
        impact = str(report.get("impact", "")).strip()
        patch = str(report.get("patch_idea", "")).strip()
        fix = str(report.get("minimal_fix", "")).strip()
        funcs = report.get("vulnerable_functions", [])
        evid = report.get("key_evidence", [])

        placeholders = {
            "",
            "未给出",
            "未确认明确漏洞类型",
            "当前证据不足，无法确认稳定的漏洞根因",
            "当前仅能确认存在潜在风险，尚不足以得出稳定漏洞结论",
            "先补充证据并确认真实漏洞点，再制定针对性修复方案",
            "当前证据不足，暂不输出具体修复代码建议",
        }
        if vuln_type in placeholders:
            raise RuntimeError("final semantic check failed: empty vulnerability type")
        if suspicious_site in placeholders:
            raise RuntimeError("final semantic check failed: empty primary suspicious site")
        if root in placeholders:
            raise RuntimeError("final semantic check failed: empty root cause")
        if trigger in placeholders:
            raise RuntimeError("final semantic check failed: empty trigger condition")
        if impact in placeholders:
            raise RuntimeError("final semantic check failed: empty impact")
        if patch in placeholders:
            raise RuntimeError("final semantic check failed: empty patch idea")
        if fix in placeholders:
            raise RuntimeError("final semantic check failed: empty minimal fix")
        if not isinstance(funcs, list) or not [str(x).strip() for x in funcs if str(x).strip()]:
            raise RuntimeError("final semantic check failed: empty vulnerable functions")
        if not isinstance(evid, list) or not [str(x).strip() for x in evid if str(x).strip()]:
            raise RuntimeError("final semantic check failed: empty key evidence")

        text_blob = "\n".join(
            [
                vuln_type,
                suspicious_site,
                root,
                trigger,
                impact,
                patch,
                fix,
                "\n".join(str(x) for x in funcs if str(x).strip()),
                "\n".join(str(x) for x in evid if str(x).strip()),
            ]
        )

        evidence_tokens: set[str] = set()
        round1 = compact_bundle.get("round1", {}) if isinstance(compact_bundle.get("round1"), dict) else {}
        snapshot = compact_bundle.get("snapshot", {}) if isinstance(compact_bundle.get("snapshot"), dict) else {}
        for name in round1.get("analysis_order", []) if isinstance(round1.get("analysis_order"), list) else []:
            token = str(name).strip()
            if token:
                evidence_tokens.add(token)
        for item in snapshot.get("dangerous_calls", []) if isinstance(snapshot.get("dangerous_calls"), list) else []:
            if not isinstance(item, dict):
                continue
            token = str(item.get("api", "")).strip()
            if token:
                evidence_tokens.add(token)

        if evidence_tokens and not any(token in text_blob for token in evidence_tokens):
            raise RuntimeError("final semantic check failed: answer does not reference evidence functions/apis")

    def _sanitize_final_report(self, report: Dict[str, Any], compact_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """按当前样本的真实函数集合清洗 final 结构，避免把导入 API 当成漏洞函数。"""
        out = dict(report)
        snapshot = compact_bundle.get("snapshot", {}) if isinstance(compact_bundle.get("snapshot"), dict) else {}
        valid_funcs = {
            str(name).strip()
            for name in snapshot.get("functions", [])
            if str(name).strip()
        }
        funcs = out.get("vulnerable_functions", [])
        if isinstance(funcs, list):
            cleaned: list[str] = []
            seen: set[str] = set()
            for name in funcs:
                token = str(name).strip()
                if not token or token not in valid_funcs or token in seen:
                    continue
                seen.add(token)
                cleaned.append(token)
            out["vulnerable_functions"] = cleaned
        return out

    def _limit_list(self, values: Any, limit: int) -> list[Any]:
        """限制列表大小，避免 prompt 过长。"""
        if not isinstance(values, list):
            return []
        return values[: max(0, limit)]

    def _truncate_text(self, text: str, limit: int) -> str:
        """限制单段文本长度。"""
        clean = " ".join(str(text).split())
        if len(clean) <= limit:
            return clean
        return clean[:limit] + " ..."

    def _compact_snapshot(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """压缩基础快照，降低大程序导致的上下文膨胀。"""
        out = dict(snapshot)
        batch_mode = bool(snapshot.get("summary", {}).get("batch_mode")) if isinstance(snapshot.get("summary"), dict) else False
        func_limit = self.snapshot_limits["functions"] if not batch_mode else min(self.snapshot_limits["functions"], 8)
        string_limit = self.snapshot_limits["strings"] if not batch_mode else min(self.snapshot_limits["strings"], 24)
        import_limit = self.snapshot_limits["imports"] if not batch_mode else min(self.snapshot_limits["imports"], 24)
        dangerous_limit = (
            self.snapshot_limits["dangerous_calls"]
            if not batch_mode
            else min(self.snapshot_limits["dangerous_calls"], 8)
        )
        funcs = self._limit_list(snapshot.get("functions"), func_limit)
        strings = self._limit_list(snapshot.get("strings"), string_limit)
        imports = self._limit_list(snapshot.get("imports"), import_limit)
        dangerous_calls = self._limit_list(snapshot.get("dangerous_calls"), dangerous_limit)

        out["functions"] = [str(x) for x in funcs]
        out["strings"] = [self._truncate_text(str(x), 120) for x in strings]
        out["imports"] = [str(x) for x in imports]
        out["dangerous_calls"] = dangerous_calls
        out["summary"] = {
            "function_count_total": len(snapshot.get("functions", [])) if isinstance(snapshot.get("functions"), list) else 0,
            "function_count_in_prompt": len(out["functions"]),
            "string_count_total": len(snapshot.get("strings", [])) if isinstance(snapshot.get("strings"), list) else 0,
            "string_count_in_prompt": len(out["strings"]),
            "import_count_total": len(snapshot.get("imports", [])) if isinstance(snapshot.get("imports"), list) else 0,
            "import_count_in_prompt": len(out["imports"]),
            "dangerous_call_count_total": (
                len(snapshot.get("dangerous_calls", [])) if isinstance(snapshot.get("dangerous_calls"), list) else 0
            ),
            "dangerous_call_count_in_prompt": len(out["dangerous_calls"]),
        }
        return out

    def _build_round1_batches(self, snapshot: Dict[str, Any]) -> list[Dict[str, Any]]:
        """按可疑函数分批构造 round1 输入，降低单次 prompt 负载。"""
        dangerous_calls = snapshot.get("dangerous_calls", []) if isinstance(snapshot.get("dangerous_calls"), list) else []
        functions = snapshot.get("functions", []) if isinstance(snapshot.get("functions"), list) else []
        postorder_functions = (
            snapshot.get("postorder_functions", []) if isinstance(snapshot.get("postorder_functions"), list) else []
        )
        imports = snapshot.get("imports", []) if isinstance(snapshot.get("imports"), list) else []
        strings = snapshot.get("strings", []) if isinstance(snapshot.get("strings"), list) else []
        batch_size = max(1, self.round1_limits["batch_size"])

        priority_funcs: list[str] = []
        dangerous_names = []
        for item in dangerous_calls:
            if not isinstance(item, dict):
                continue
            name = str(item.get("function", "")).strip()
            if name and not name.startswith(self._MANUAL_SKIP_PREFIX) and name not in dangerous_names:
                dangerous_names.append(name)

        for fn in postorder_functions:
            name = str(fn).strip()
            if not name or name.startswith(self._MANUAL_SKIP_PREFIX):
                continue
            if name in dangerous_names and name not in priority_funcs:
                priority_funcs.append(name)

        ordered_functions = postorder_functions or functions
        for fn in ordered_functions:
            name = str(fn).strip()
            if name and not name.startswith(self._MANUAL_SKIP_PREFIX) and name not in priority_funcs:
                priority_funcs.append(name)

        batches: list[Dict[str, Any]] = []
        for idx in range(0, len(priority_funcs), batch_size):
            batch_funcs = priority_funcs[idx : idx + batch_size]
            batch_dangerous_calls = []
            for item in dangerous_calls:
                if not isinstance(item, dict):
                    continue
                if str(item.get("function", "")).strip() in batch_funcs:
                    batch_dangerous_calls.append(item)

            batches.append(
                {
                    "binary": snapshot.get("binary", ""),
                    "architecture": snapshot.get("architecture", ""),
                    "entry_point": snapshot.get("entry_point", ""),
                    "root_function": str(snapshot.get("root_function", "")).strip(),
                    "postorder_functions": batch_funcs,
                    "imports": imports,
                    "strings": strings,
                    "functions": batch_funcs,
                    "dangerous_calls": batch_dangerous_calls,
                    "summary": {
                        "batch_index": len(batches) + 1,
                        "batch_function_count": len(batch_funcs),
                        "total_function_count": len(ordered_functions),
                        "root_function": str(snapshot.get("root_function", "")).strip(),
                        "analysis_order": "dfs_postorder_leaf_first",
                        "dangerous_call_count_in_batch": len(batch_dangerous_calls),
                        "batch_mode": True,
                    },
                }
            )
        return batches

    def _compact_evidence_bundle(self, evidence_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """压缩二轮证据包，优先保留结构化信息和伪代码摘要。"""
        out = dict(evidence_bundle)
        round2 = evidence_bundle.get("round2", {}) if isinstance(evidence_bundle.get("round2"), dict) else {}
        items = round2.get("evidence_items", []) if isinstance(round2.get("evidence_items"), list) else []

        round1 = evidence_bundle.get("round1", {}) if isinstance(evidence_bundle.get("round1"), dict) else {}
        order = round1.get("analysis_order", []) if isinstance(round1.get("analysis_order"), list) else []
        order_index = {str(name).strip(): idx for idx, name in enumerate(order) if str(name).strip()}

        def _item_score(item: Dict[str, Any]) -> tuple[int, int, int, int]:
            req = item.get("request", {}) if isinstance(item.get("request"), dict) else {}
            res = item.get("result", {}) if isinstance(item.get("result"), dict) else {}
            tool = str(req.get("tool", "")).strip()
            target = str(req.get("target", "")).strip() or str(res.get("target", "")).strip()

            manual_suppressed = 1 if target.startswith(self._MANUAL_SKIP_PREFIX) else 0
            helper_like = 1 if target.startswith("sub_") or target.startswith(self._MANUAL_SKIP_PREFIX) else 0
            tool_rank = 0 if tool == "get_pseudocode" else 1
            order_rank = order_index.get(target, 10**6)
            return (manual_suppressed, helper_like, tool_rank, order_rank)

        ordered_items = sorted(
            [item for item in items if isinstance(item, dict)],
            key=_item_score,
        )

        compact_items = []
        for item in ordered_items[: self.evidence_limits["evidence_items"]]:
            req = item.get("request", {}) if isinstance(item.get("request"), dict) else {}
            res = item.get("result", {}) if isinstance(item.get("result"), dict) else {}
            compact_res = dict(res)
            if isinstance(compact_res.get("items"), list):
                compact_res["items"] = [str(x) for x in compact_res["items"][: self.evidence_limits["items_preview"]]]
                compact_res["items_total"] = len(res.get("items", []))
            if "text" in compact_res:
                compact_res["text"] = self._truncate_text(
                    str(compact_res.get("text", "")),
                    self.evidence_limits["text_chars"],
                )
            compact_items.append({"request": req, "result": compact_res})

        out["round2"] = {
            **round2,
            "evidence_items": compact_items,
            "summary": {
                "evidence_items_total": len(items),
                "evidence_items_in_prompt": len(compact_items),
            },
        }
        return out

    def _to_zh_text(self, s: str) -> str:
        """常见英文术语转中文（降低阅读负担）。"""
        text = str(s or "")
        replacements = {
            "Heap corruption": "堆破坏",
            "arbitrary code execution": "任意代码执行",
            "program crash": "程序崩溃",
            "Validate the size before allocating and reading": "在分配与读取前校验大小",
            "ensure the read length does not exceed the allocated buffer": "确保读取长度不超过已分配缓冲区",
            "replace unsafe read patterns with bounds-checked functions": "将不安全读取模式替换为带边界检查的函数",
            "Modify": "修改",
            "Inspect": "检查",
            "Verify": "验证",
            "Check": "检查",
            "Heap overflow": "堆溢出",
            "tcache poisoning": "tcache 污染",
        }
        for en, zh in replacements.items():
            text = text.replace(en, zh)
        return text

    def _localize_final_fields(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """将最终报告关键字段本地化成中文。"""
        out = dict(report)
        for k in [
            "primary_suspicious_site",
            "suspected_vulnerability_type",
            "root_cause",
            "trigger_condition",
            "impact",
            "patch_idea",
            "minimal_fix",
        ]:
            if k in out:
                out[k] = self._to_zh_text(str(out.get(k, "")))

        for k in ["vulnerable_functions", "key_evidence", "manual_checks"]:
            v = out.get(k, [])
            if isinstance(v, list):
                out[k] = [self._to_zh_text(str(x)) for x in v]

        locations = out.get("vulnerability_locations", [])
        if isinstance(locations, list):
            cleaned_locations = []
            for item in locations:
                if not isinstance(item, dict):
                    continue
                cleaned_locations.append(
                    {
                        "function": str(item.get("function", "")).strip(),
                        "address": str(item.get("address", "")).strip(),
                        "statement": self._to_zh_text(str(item.get("statement", "")).strip()),
                        "source": self._to_zh_text(str(item.get("source", "")).strip()),
                    }
                )
            out["vulnerability_locations"] = cleaned_locations
        return out

    def _derive_vulnerability_locations(
        self,
        report: Dict[str, Any],
        evidence_bundle: Dict[str, Any],
    ) -> list[Dict[str, str]]:
        """根据 round2 证据为最终报告补充稳定的漏洞位置。"""
        funcs = [
            str(name).strip()
            for name in report.get("vulnerable_functions", [])
            if str(name).strip()
        ]
        if not funcs:
            return []

        round2 = evidence_bundle.get("round2", {}) if isinstance(evidence_bundle.get("round2"), dict) else {}
        evidence_items = round2.get("evidence_items", []) if isinstance(round2.get("evidence_items"), list) else []
        evidence_map: Dict[str, Dict[str, Any]] = {}
        for item in evidence_items:
            if not isinstance(item, dict):
                continue
            req = item.get("request", {}) if isinstance(item.get("request"), dict) else {}
            if str(req.get("tool", "")).strip() != "get_pseudocode":
                continue
            res = item.get("result", {}) if isinstance(item.get("result"), dict) else {}
            target = str(req.get("target", "")).strip() or str(res.get("target", "")).strip()
            if target and target not in evidence_map:
                evidence_map[target] = res

        context_tokens = self._extract_location_tokens(report)
        out: list[Dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for func in funcs:
            res = evidence_map.get(func)
            if not isinstance(res, dict):
                continue
            statement = self._pick_location_statement(str(res.get("text", "")), context_tokens)
            addr = str(res.get("function_ea", "")).strip() or self._infer_function_ea_from_text(str(res.get("text", "")))
            source = "伪代码" if str(res.get("kind", "")).strip() == "pseudocode" else "汇编"
            key = (func, addr, statement)
            if statement and key not in seen:
                seen.add(key)
                out.append(
                    {
                        "function": func,
                        "address": addr,
                        "statement": statement,
                        "source": source,
                    }
                )
        return out

    def _infer_function_ea_from_text(self, text: str) -> str:
        """从旧版伪代码/汇编文本中尽量反推函数地址。"""
        m = re.search(r"\bsub_([0-9A-Fa-f]{3,})\b", text)
        if m:
            return f"0x{m.group(1).lower()}"
        m = re.search(r"\b(0x[0-9A-Fa-f]+):", text)
        if m:
            return m.group(1).lower()
        return "未知地址"

    def _extract_location_tokens(self, report: Dict[str, Any]) -> list[str]:
        """从最终报告文本中提取与位置匹配相关的关键词。"""
        corpus = "\n".join(
            [
                str(report.get("root_cause", "")),
                str(report.get("trigger_condition", "")),
                str(report.get("patch_idea", "")),
                str(report.get("minimal_fix", "")),
                "\n".join(str(x) for x in report.get("key_evidence", []) if str(x).strip()),
            ]
        )
        tokens: list[str] = []
        seen: set[str] = set()
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_\[\]]{2,}", corpus):
            clean = token.strip()
            lower = clean.lower()
            if lower in seen or lower.startswith("0x"):
                continue
            seen.add(lower)
            tokens.append(clean)
        return tokens

    def _pick_location_statement(self, text: str, context_tokens: list[str]) -> str:
        """从函数伪代码/汇编中挑选最像漏洞点的一行。"""
        best_line = ""
        best_score = -1
        generic_keywords = [
            "scanf",
            "read",
            "recv",
            "memcpy",
            "strcpy",
            "strncpy",
            "strcat",
            "sprintf",
            "snprintf",
            "malloc",
            "calloc",
            "realloc",
            "free",
            "system",
            "exec",
            "gets",
            "size",
            "len",
            "index",
        ]
        for raw in text.splitlines():
            line = " ".join(str(raw).strip().split())
            if not line or line in {"{", "}"}:
                continue
            score = 0
            lower = line.lower()
            if lower.startswith("unsigned ") or lower.startswith("void ") or lower.startswith("__int64 "):
                score -= 1
            if "//" in line:
                score += 1
            if any(keyword in lower for keyword in generic_keywords):
                score += 3
            if "if (" in line or ("=" in line and "(" in line and ")" in line):
                score += 1
            if any(token.lower() in lower for token in context_tokens):
                score += 4
            if "__readfsqword" in line:
                score -= 2
            if score > best_score:
                best_score = score
                best_line = line

        if len(best_line) > 220:
            return best_line[:220] + " ..."
        return best_line

    def _merge_unique_strings(self, base: list[str], incoming: list[Any]) -> list[str]:
        """按出现顺序去重合并字符串列表。"""
        out = [str(x) for x in base]
        seen = set(out)
        for item in incoming:
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)
        return out

    def _merge_round1_results(self, current: Dict[str, Any] | None, incoming: Dict[str, Any]) -> Dict[str, Any]:
        """把多个批次的 round1 结果聚合为单个 schema 对象。"""
        if current is None:
            current = {
                "analysis_order": [],
                "function_summaries": [],
                "semantic_renames": [],
                "suspicious_functions": [],
                "hypotheses": [],
                "evidence_gaps": [],
                "next_evidence_requests": [],
            }

        current["analysis_order"] = self._merge_unique_strings(current["analysis_order"], incoming.get("analysis_order", []))

        seen_summary_names = {
            str(item.get("name", "")).strip()
            for item in current["function_summaries"]
            if isinstance(item, dict)
        }
        for item in incoming.get("function_summaries", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name or name in seen_summary_names:
                continue
            seen_summary_names.add(name)
            current["function_summaries"].append(
                {
                    "name": name,
                    "role": str(item.get("role", "作用未明")).strip() or "作用未明",
                    "suspicious": str(item.get("suspicious", "no")).strip().lower() or "no",
                    "reason": str(item.get("reason", "暂无明确异常")).strip() or "暂无明确异常",
                    "rename_suggestion": str(item.get("rename_suggestion", "")).strip(),
                }
            )

        seen_renames = {
            str(item.get("original_name", "")).strip()
            for item in current["semantic_renames"]
            if isinstance(item, dict)
        }
        for item in incoming.get("semantic_renames", []):
            if not isinstance(item, dict):
                continue
            original_name = str(item.get("original_name", "")).strip()
            suggested_name = str(item.get("suggested_name", "")).strip()
            reason = str(item.get("reason", "")).strip()
            if not original_name or not suggested_name or original_name in seen_renames:
                continue
            seen_renames.add(original_name)
            current["semantic_renames"].append(
                {
                    "original_name": original_name,
                    "suggested_name": suggested_name,
                    "reason": reason or "基于函数职责给出语义化命名建议",
                }
            )

        seen_funcs = {str(item.get("name", "")).strip() for item in current["suspicious_functions"] if isinstance(item, dict)}
        for item in incoming.get("suspicious_functions", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name or name in seen_funcs:
                continue
            if name.startswith(self._MANUAL_SKIP_PREFIX):
                continue
            seen_funcs.add(name)
            current["suspicious_functions"].append(
                {
                    "name": name,
                    "reason": str(item.get("reason", "存在可疑行为")).strip() or "存在可疑行为",
                }
            )

        current["hypotheses"] = self._merge_unique_strings(current["hypotheses"], incoming.get("hypotheses", []))
        current["evidence_gaps"] = self._merge_unique_strings(current["evidence_gaps"], incoming.get("evidence_gaps", []))

        current["next_evidence_requests"].extend(
            incoming.get("next_evidence_requests", []) if isinstance(incoming.get("next_evidence_requests"), list) else []
        )
        current["next_evidence_requests"] = self._dedupe_requests(current["next_evidence_requests"])

        return current

    def _finalize_round1_result(self, merged: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """限制聚合结果体积，并保证输出稳定。"""
        suspects = merged.get("suspicious_functions", [])
        if not isinstance(suspects, list):
            suspects = []

        order = snapshot.get("postorder_functions", []) if isinstance(snapshot.get("postorder_functions"), list) else []
        if order:
            merged["analysis_order"] = [str(x) for x in order if str(x).strip()]
            summary_by_name = {
                str(item.get("name", "")).strip(): item
                for item in merged.get("function_summaries", [])
                if isinstance(item, dict)
            }
            reordered = []
            for name in merged["analysis_order"]:
                item = summary_by_name.get(name)
                if item:
                    reordered.append(item)
            for item in merged.get("function_summaries", []):
                if isinstance(item, dict) and item not in reordered:
                    reordered.append(item)
            merged["function_summaries"] = reordered

        rename_by_name = {
            str(item.get("original_name", "")).strip(): item
            for item in merged.get("semantic_renames", [])
            if isinstance(item, dict)
        }
        ordered_renames = []
        for name in merged.get("analysis_order", []):
            item = rename_by_name.get(str(name).strip())
            if item:
                ordered_renames.append(item)
        for item in merged.get("semantic_renames", []):
            if isinstance(item, dict) and item not in ordered_renames:
                ordered_renames.append(item)
        merged["semantic_renames"] = ordered_renames

        requests = merged.get("next_evidence_requests", [])
        if isinstance(requests, list):
            merged["next_evidence_requests"] = self._dedupe_requests(requests)[: self.round1_limits["max_requests"]]

        if not merged.get("hypotheses"):
            merged["hypotheses"] = ["当前证据不足，尚未确认明确漏洞类型"]
        if not merged.get("evidence_gaps"):
            merged["evidence_gaps"] = ["缺少足够的函数级证据，需继续在 IDA 中补充调用关系与关键代码片段"]
        return merged

    def _sanitize_round1_result(self, result: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """按当前快照的真实函数集合清洗 round1 输出，避免把导入/API 填进函数字段。"""
        out = dict(result)
        valid_funcs = {
            str(name).strip()
            for name in snapshot.get("functions", [])
            if str(name).strip()
        }

        analysis_order = out.get("analysis_order", [])
        if isinstance(analysis_order, list):
            cleaned_order: list[str] = []
            seen_order: set[str] = set()
            for item in analysis_order:
                name = str(item).strip()
                if not name or name not in valid_funcs or name in seen_order:
                    continue
                seen_order.add(name)
                cleaned_order.append(name)
            out["analysis_order"] = cleaned_order

        summaries = out.get("function_summaries", [])
        if isinstance(summaries, list):
            cleaned_summaries: list[Dict[str, Any]] = []
            seen_summary_names: set[str] = set()
            for item in summaries:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).strip()
                if not name or name not in valid_funcs or name in seen_summary_names:
                    continue
                seen_summary_names.add(name)
                cleaned_summaries.append(item)
            out["function_summaries"] = cleaned_summaries

        suspects = out.get("suspicious_functions", [])
        if isinstance(suspects, list):
            cleaned_suspects: list[Dict[str, str]] = []
            seen_suspects: set[str] = set()
            for item in suspects:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).strip()
                reason = str(item.get("reason", "")).strip()
                if not name or name not in valid_funcs or name in seen_suspects:
                    continue
                seen_suspects.add(name)
                cleaned_suspects.append({"name": name, "reason": reason or "存在可疑行为"})
            out["suspicious_functions"] = cleaned_suspects

        requests = out.get("next_evidence_requests", [])
        if isinstance(requests, list):
            cleaned_requests: list[Dict[str, str]] = []
            seen_requests: set[tuple[str, str]] = set()
            for item in requests:
                if not isinstance(item, dict):
                    continue
                tool = str(item.get("tool", "")).strip()
                target = str(item.get("target", "")).strip()
                if not tool or not target or target not in valid_funcs:
                    continue
                key = (tool, target)
                if key in seen_requests:
                    continue
                seen_requests.add(key)
                cleaned_requests.append({"tool": tool, "target": target})
            out["next_evidence_requests"] = cleaned_requests

        return out

    def _suggest_semantic_name(self, name: str, role: str, reason: str) -> str:
        """为 `sub_` 风格函数生成稳定的语义化命名建议。"""
        clean = str(name).strip()
        if not clean.startswith("sub_"):
            return ""

        text = f"{role} {reason}".lower()
        if "read" in text or "输入" in text or "读取" in text:
            prefix = "handle_input"
        elif "parse" in text or "解析" in text:
            prefix = "parse_data"
        elif "copy" in text or "拷贝" in text:
            prefix = "copy_buffer"
        elif "check" in text or "校验" in text or "verify" in text:
            prefix = "validate_state"
        elif "alloc" in text or "malloc" in text or "分配" in text:
            prefix = "allocate_buffer"
        else:
            prefix = "analyze_target"
        suffix = clean[4:].lower() or "func"
        return f"{prefix}_{suffix}"

    def _dedupe_requests(self, items: list[Any]) -> list[Dict[str, str]]:
        """按 tool/target 去重补证请求，避免重复分析。"""
        deduped: list[Dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool", "")).strip()
            target = str(item.get("target", "")).strip()
            if not tool or not target or (tool, target) in seen:
                continue
            seen.add((tool, target))
            deduped.append({"tool": tool, "target": target})
        return deduped

    def _coerce_round1(self, obj: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
        raise RuntimeError("round1 coerce 已禁用；模型输出缺字段时应直接失败")

    def _coerce_final(self, obj: Dict[str, Any], evidence_bundle: Dict[str, Any]) -> Dict[str, Any]:
        raise RuntimeError("final coerce 已禁用；模型输出缺字段时应直接失败")

    def _build_semantic_renames(self, evidence_bundle: Dict[str, Any]) -> list[Dict[str, str]]:
        """从 round1 汇总 `sub_` 函数改名建议，供最终报告复用。"""
        round1 = evidence_bundle.get("round1", {}) if isinstance(evidence_bundle.get("round1"), dict) else {}
        items = round1.get("semantic_renames", []) if isinstance(round1.get("semantic_renames"), list) else []
        out: list[Dict[str, str]] = []
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            original_name = str(item.get("original_name", "")).strip()
            suggested_name = str(item.get("suggested_name", "")).strip()
            reason = str(item.get("reason", "")).strip() or "基于函数职责给出语义化命名建议"
            if not original_name or not suggested_name or original_name in seen:
                continue
            seen.add(original_name)
            out.append(
                {
                    "original_name": original_name,
                    "suggested_name": suggested_name,
                    "reason": reason,
                }
            )
        return out
