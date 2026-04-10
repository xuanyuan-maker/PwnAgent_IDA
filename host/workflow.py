from __future__ import annotations

"""线性工作流引擎（瀑布流状态机）。"""

from datetime import datetime
from typing import Dict, Any, Callable

from .models import Stage, TaskManifest
from .storage import TaskStorage
from .ida_bridge_interface import IDAEvidenceBridge
from .model_adapter import ModelAdapter
from .reporting import render_markdown
from .schema_validator import SimpleSchemaValidator
from .logger import get_logger, current_request_id

logger = get_logger("workflow")


NEXT_STAGE = {
    Stage.INIT.value: Stage.BASE_SNAPSHOT.value,
    Stage.BASE_SNAPSHOT.value: Stage.ROUND1_ANALYSIS.value,
    Stage.ROUND1_ANALYSIS.value: Stage.ROUND2_EVIDENCE.value,
    Stage.ROUND2_EVIDENCE.value: Stage.FINAL_ANALYSIS.value,
    Stage.FINAL_ANALYSIS.value: Stage.EXPORT.value,
    Stage.EXPORT.value: Stage.DONE.value,
}


class WorkflowEngine:
    """驱动完整分析流程。"""

    _MANUAL_SKIP_PREFIX = "NO_"

    def __init__(
        self,
        storage: TaskStorage,
        model: ModelAdapter,
        ida: IDAEvidenceBridge,
        schema_validator: SimpleSchemaValidator | None = None,
        agent_models: Dict[str, str] | None = None,
        verifier_on_high_risk: bool = True,
        progress_callback: Callable[[Dict[str, Any]], None] | None = None,
        round2_max_suspects: int = 3,
    ):
        self.storage = storage
        self.model = model
        self.ida = ida
        self.schema_validator = schema_validator
        # 多角色模型映射：scout / judge / verifier
        self.agent_models = agent_models or {}
        self.verifier_on_high_risk = verifier_on_high_risk
        self.progress_callback = progress_callback
        self.round2_max_suspects = max(1, int(round2_max_suspects))

    def _notify(self, payload: Dict[str, Any]) -> None:
        """向外部前端回传阶段进度。"""
        if not self.progress_callback:
            return
        try:
            data = dict(payload)
            data.setdefault("request_id", current_request_id())
            self.progress_callback(data)
        except Exception:
            pass

    def _log(self, task_id: str, msg: str) -> None:
        """把阶段日志追加到任务目录 runtime.log（便于赛后复盘）。"""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        p = self.storage.task_dir(task_id) / "runtime.log"
        with p.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
        logger.info("task=%s %s", task_id, msg)
        self._notify({"event": "log", "task_id": task_id, "message": msg, "time": ts})

    def run(self, manifest: TaskManifest) -> TaskManifest:
        """从当前阶段持续推进到 DONE。"""
        self._log(manifest.task_id, f"workflow start, stage={manifest.stage}")
        self._notify({"event": "start", "task_id": manifest.task_id, "stage": manifest.stage})
        while manifest.stage != Stage.DONE.value:
            prev = manifest.stage
            try:
                self._step(manifest)
            except Exception as e:
                self._log(manifest.task_id, f"error at stage={prev}: {e}")
                self._notify(
                    {
                        "event": "error",
                        "task_id": manifest.task_id,
                        "stage": prev,
                        "message": str(e),
                    }
                )
                raise
            self.storage.save_manifest(manifest)
            self._log(manifest.task_id, f"stage {prev} -> {manifest.stage}")
            self._notify(
                {
                    "event": "stage",
                    "task_id": manifest.task_id,
                    "stage": manifest.stage,
                    "previous_stage": prev,
                }
            )
        self._log(manifest.task_id, "workflow done")
        self._notify({"event": "done", "task_id": manifest.task_id, "stage": manifest.stage})
        return manifest

    def _risk_level(self, report: Dict[str, Any]) -> str:
        """标准化风险级别。"""
        risk = str(report.get("false_positive_risk", "")).strip().lower()
        if risk in {"low", "medium", "high"}:
            return risk
        return "medium"

    def _validate_round1(self, round1: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """严格校验 round1 结构与关键语义；不做任何兜底修复。"""
        if self.schema_validator:
            self.schema_validator.validate_named("analysis_round1.schema.json", round1)

        valid_funcs = {str(x).strip() for x in snapshot.get("functions", []) if str(x).strip()}
        invalid_names = []
        for item in round1.get("suspicious_functions", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            if name not in valid_funcs:
                invalid_names.append(name)
        if invalid_names:
            raise RuntimeError(
                "round1 suspicious_functions 包含非函数名目标: " + ", ".join(sorted(set(invalid_names)))
            )

    def _validate_final(self, report: Dict[str, Any], snapshot: Dict[str, Any]) -> None:
        """校验 final 结构与关键语义；不接受占位式结论。"""
        if self.schema_validator:
            self.schema_validator.validate_named("final_report.schema.json", report)

        valid_funcs = {str(x).strip() for x in snapshot.get("functions", []) if str(x).strip()}
        vuln_type = str(report.get("suspected_vulnerability_type", "")).strip()
        root_cause = str(report.get("root_cause", "")).strip()
        trigger = str(report.get("trigger_condition", "")).strip()
        impact = str(report.get("impact", "")).strip()
        patch = str(report.get("patch_idea", "")).strip()
        fix = str(report.get("minimal_fix", "")).strip()
        vuln_funcs = report.get("vulnerable_functions", [])
        key_evidence = report.get("key_evidence", [])

        placeholders = {
            "",
            "未给出",
            "未确认明确漏洞类型",
            "当前证据不足，无法确认稳定的漏洞根因",
            "当前仅能确认存在潜在风险，尚不足以得出稳定漏洞结论",
            "当前证据不足，暂不输出具体修复代码建议",
            "先补充证据并确认真实漏洞点，再制定针对性修复方案",
        }

        if vuln_type in placeholders or "|" in vuln_type or vuln_type.startswith("\"suspected_vulnerability_type\""):
            raise RuntimeError(f"final suspected_vulnerability_type 无效: {vuln_type!r}")
        if root_cause in placeholders:
            raise RuntimeError("final root_cause 仍为占位文本")
        if trigger in placeholders:
            raise RuntimeError("final trigger_condition 仍为占位文本")
        if impact in placeholders:
            raise RuntimeError("final impact 仍为占位文本")
        if patch in placeholders:
            raise RuntimeError("final patch_idea 仍为占位文本")
        if fix in placeholders:
            raise RuntimeError("final minimal_fix 仍为占位文本")
        if not isinstance(vuln_funcs, list) or not vuln_funcs:
            raise RuntimeError("final vulnerable_functions 为空")
        invalid_funcs = [name for name in vuln_funcs if str(name).strip() not in valid_funcs]
        if invalid_funcs:
            raise RuntimeError("final vulnerable_functions 包含非函数名目标: " + ", ".join(sorted(set(invalid_funcs))))
        if not isinstance(key_evidence, list) or not [str(x).strip() for x in key_evidence if str(x).strip()]:
            raise RuntimeError("final key_evidence 为空")

    def _round2_priority_targets(self, snapshot: Dict[str, Any], limit: int = 3) -> list[str]:
        """为 round2 强制补充高价值函数，避免模型漏掉真正的漏洞点。"""
        out: list[str] = []
        seen: set[str] = set()

        def _append(name: Any) -> None:
            clean = str(name).strip()
            if not clean or clean in seen or clean.startswith(self._MANUAL_SKIP_PREFIX):
                return
            seen.add(clean)
            out.append(clean)

        for name in snapshot.get("priority_functions", []) if isinstance(snapshot.get("priority_functions"), list) else []:
            _append(name)
            if len(out) >= limit:
                return out

        for item in snapshot.get("dangerous_calls", []) if isinstance(snapshot.get("dangerous_calls"), list) else []:
            if not isinstance(item, dict):
                continue
            _append(item.get("function", ""))
            if len(out) >= limit:
                return out

        return out

    def _dedupe_evidence_requests(self, requests: list[Dict[str, str]]) -> list[Dict[str, str]]:
        """按 tool/target 去重，避免重复补证。"""
        out: list[Dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in requests:
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool", "")).strip()
            target = str(item.get("target", "")).strip()
            if target.startswith(self._MANUAL_SKIP_PREFIX):
                continue
            if not tool or not target or (tool, target) in seen:
                continue
            seen.add((tool, target))
            out.append({"tool": tool, "target": target})
        return out

    def _step(self, manifest: TaskManifest) -> None:
        """执行单步状态迁移。"""
        if manifest.stage == Stage.INIT.value:
            manifest.stage = NEXT_STAGE[manifest.stage]
            return

        if manifest.stage == Stage.BASE_SNAPSHOT.value:
            # 阶段2：采集基础快照
            snapshot = self.ida.base_snapshot(manifest.binary_path)
            self.storage.save_json(manifest.task_id, "snapshot_base.json", snapshot)
            manifest.stage = NEXT_STAGE[manifest.stage]
            return

        if manifest.stage == Stage.ROUND1_ANALYSIS.value:
            # 阶段3：首轮分析（scout）
            snapshot = self.storage.load_json(manifest.task_id, "snapshot_base.json")
            try:
                round1 = self.model.analyze_round1(
                    snapshot,
                    model_name=self.agent_models.get("scout"),
                )
            except Exception:
                self.model.dump_last_raw_outputs(self.storage.task_dir(manifest.task_id), "round1")
                raise
            try:
                self._validate_round1(round1, snapshot)
            except Exception:
                self.model.dump_last_raw_outputs(self.storage.task_dir(manifest.task_id), "round1")
                raise
            self.storage.save_json(manifest.task_id, "analysis_round1.json", round1)
            manifest.stage = NEXT_STAGE[manifest.stage]
            return

        if manifest.stage == Stage.ROUND2_EVIDENCE.value:
            # 阶段4：根据首轮结果补证
            round1 = self.storage.load_json(manifest.task_id, "analysis_round1.json")
            snapshot = self.storage.load_json(manifest.task_id, "snapshot_base.json")
            reqs = list(round1.get("next_evidence_requests", []))

            # 增强证据：自动补 1~3 个可疑函数伪代码/汇编片段
            suspects = round1.get("suspicious_functions", [])
            for s in suspects[: self.round2_max_suspects]:
                if not isinstance(s, dict):
                    continue
                name = s.get("name")
                if not name or str(name).startswith(self._MANUAL_SKIP_PREFIX):
                    continue
                reqs.append({"tool": "get_pseudocode", "target": name})

            # 强制补证高优先级危险函数，避免 round1 漏掉真实漏洞点。
            for name in self._round2_priority_targets(snapshot, limit=max(self.round2_max_suspects, 5)):
                reqs.append({"tool": "get_pseudocode", "target": name})

            reqs = self._dedupe_evidence_requests(reqs)
            evidence = self.ida.collect_round2_evidence(reqs)
            self.storage.save_json(manifest.task_id, "evidence_round2.json", evidence)
            manifest.stage = NEXT_STAGE[manifest.stage]
            return

        if manifest.stage == Stage.FINAL_ANALYSIS.value:
            # 阶段5：最终结论（judge）+ 可选复核（verifier）
            snapshot = self.storage.load_json(manifest.task_id, "snapshot_base.json")
            round1 = self.storage.load_json(manifest.task_id, "analysis_round1.json")
            evidence = self.storage.load_json(manifest.task_id, "evidence_round2.json")
            bundle: Dict[str, Any] = {
                "snapshot": snapshot,
                "round1": round1,
                "round2": evidence,
            }

            judge_model = self.agent_models.get("judge")
            try:
                final_report = self.model.analyze_final(bundle, model_name=judge_model)
            except Exception:
                self.model.dump_last_raw_outputs(self.storage.task_dir(manifest.task_id), "final")
                raise
            final_report["analysis_order"] = list(round1.get("analysis_order", []))
            final_report["function_summaries"] = list(round1.get("function_summaries", []))
            final_report["semantic_renames"] = list(round1.get("semantic_renames", []))
            try:
                self._validate_final(final_report, snapshot)
            except Exception:
                self.model.dump_last_raw_outputs(self.storage.task_dir(manifest.task_id), "final")
                raise

            verifier_model = self.agent_models.get("verifier")
            verifier_report: Dict[str, Any] | None = None
            should_verify = bool(verifier_model)
            if should_verify and self.verifier_on_high_risk:
                should_verify = self._risk_level(final_report) == "high"

            if should_verify:
                verify_bundle = {
                    **bundle,
                    "judge_report": final_report,
                    "verification_mode": True,
                }
                try:
                    verifier_report = self.model.analyze_final(verify_bundle, model_name=verifier_model)
                except Exception:
                    self.model.dump_last_raw_outputs(self.storage.task_dir(manifest.task_id), "verifier")
                    raise
                verifier_report["analysis_order"] = list(round1.get("analysis_order", []))
                verifier_report["function_summaries"] = list(round1.get("function_summaries", []))
                verifier_report["semantic_renames"] = list(round1.get("semantic_renames", []))
                try:
                    self._validate_final(verifier_report, snapshot)
                except Exception:
                    self.model.dump_last_raw_outputs(self.storage.task_dir(manifest.task_id), "verifier")
                    raise

                # 把 judge/verifier 的意见都写入总报告，便于赛后复盘
                judge_report = dict(final_report)
                final_report["agent_opinions"] = {
                    "judge": judge_report,
                    "verifier": verifier_report,
                }
                final_report["consensus"] = {
                    "same_vuln_type": (
                        str(final_report.get("suspected_vulnerability_type", "")).strip().lower()
                        == str(verifier_report.get("suspected_vulnerability_type", "")).strip().lower()
                    ),
                    "same_risk": self._risk_level(final_report) == self._risk_level(verifier_report),
                }

            self.storage.save_json(manifest.task_id, "final_report.json", final_report)
            if verifier_report is not None:
                self.storage.save_json(manifest.task_id, "verification_report.json", verifier_report)
            manifest.stage = NEXT_STAGE[manifest.stage]
            return

        if manifest.stage == Stage.EXPORT.value:
            # 阶段6：导出人类可读 Markdown
            final_report = self.storage.load_json(manifest.task_id, "final_report.json")
            task_dir = self.storage.task_dir(manifest.task_id)
            md = render_markdown(manifest.task_id, manifest.to_dict(), final_report)
            (task_dir / "final_report.md").write_text(md, encoding="utf-8")
            manifest.stage = NEXT_STAGE[manifest.stage]
            return

        raise RuntimeError(f"Unknown stage: {manifest.stage}")
