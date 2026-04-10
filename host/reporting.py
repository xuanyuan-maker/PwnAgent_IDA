from __future__ import annotations

"""报告渲染层：把结构化 JSON 转为人类可读 Markdown。"""

from typing import Dict, Any, List

from .logger import get_logger

logger = get_logger("reporting")


def _bullets(items: List[str]) -> str:
    """把字符串列表渲染成 Markdown 列表，并做长度裁剪。"""
    pretty = []
    for x in items or []:
        s = str(x).strip().replace("\n", " ")
        if len(s) > 220:
            s = s[:220] + " ..."
        pretty.append(s)
    return "\n".join([f"- {x}" for x in pretty]) if pretty else "- （无）"


def _risk_zh(level: str) -> str:
    """风险级别英文字段 -> 中文。"""
    m = {"low": "低", "medium": "中", "high": "高"}
    k = str(level or "").strip().lower()
    return m.get(k, str(level or "无"))


def _function_notes(items: List[Dict[str, Any]]) -> str:
    """渲染函数级职责/风险摘要。"""
    if not items:
        return "- （无）"

    lines = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "未知函数")).strip() or "未知函数"
        role = str(item.get("role", "作用未明")).strip() or "作用未明"
        suspicious = str(item.get("suspicious", "no")).strip().lower()
        reason = str(item.get("reason", "暂无说明")).strip() or "暂无说明"
        rename_suggestion = str(item.get("rename_suggestion", "")).strip()
        flag = "可疑" if suspicious == "yes" else "未见明显异常"
        rename_text = f"；建议改名：`{rename_suggestion}`" if rename_suggestion else ""
        lines.append(f"- `{name}`: {role}；判断：{flag}；说明：{reason}{rename_text}")
    return "\n".join(lines) if lines else "- （无）"


def _semantic_renames(items: List[Dict[str, Any]]) -> str:
    """渲染 `sub_` 函数语义化改名建议。"""
    if not items:
        return "- （无）"

    lines = []
    for item in items:
        if not isinstance(item, dict):
            continue
        original_name = str(item.get("original_name", "")).strip()
        suggested_name = str(item.get("suggested_name", "")).strip()
        reason = str(item.get("reason", "")).strip() or "基于函数职责给出语义化命名建议"
        if not original_name or not suggested_name:
            continue
        lines.append(f"- `{original_name}` -> `{suggested_name}`：{reason}")
    return "\n".join(lines) if lines else "- （无）"


def _vulnerability_locations(items: List[Dict[str, Any]]) -> str:
    """渲染漏洞位置，展示函数、地址与关键语句。"""
    if not items:
        return "- （无）"

    lines = []
    for item in items:
        if not isinstance(item, dict):
            continue
        func = str(item.get("function", "")).strip() or "未知函数"
        addr = str(item.get("address", "")).strip() or "未知地址"
        stmt = str(item.get("statement", "")).strip() or "未提取到关键语句"
        source = str(item.get("source", "")).strip()
        if len(stmt) > 220:
            stmt = stmt[:220] + " ..."
        source_text = f"（{source}）" if source else ""
        lines.append(f"- `{func}` @ `{addr}`{source_text}：{stmt}")
    return "\n".join(lines) if lines else "- （无）"


def render_markdown(task_id: str, manifest: Dict[str, Any], report: Dict[str, Any]) -> str:
    """生成最终 Markdown 报告。"""
    logger.info("render_markdown: task=%s", task_id)
    consensus = report.get("consensus", {}) if isinstance(report.get("consensus"), dict) else {}
    consensus_text = ""
    if consensus:
        consensus_text = (
            "\n## 多模型一致性\n"
            f"- 漏洞类型一致：`{consensus.get('same_vuln_type', False)}`\n"
            f"- 风险评级一致：`{consensus.get('same_risk', False)}`\n"
        )

    return f"""# PWN 分析报告

- 任务ID：`{task_id}`
- 二进制：`{manifest.get('binary_path', '')}`
- IDB：`{manifest.get('idb_path', '')}`
- 模型：`{manifest.get('model_name', '')}`

## 最可疑位置
{report.get('primary_suspicious_site', '无')}

## 疑似漏洞类型
{report.get('suspected_vulnerability_type', '无')}

## 漏洞函数
{_bullets(report.get('vulnerable_functions', []))}

## 漏洞位置
{_vulnerability_locations(report.get('vulnerability_locations', []))}

## 根因定位
{report.get('root_cause', '无')}

## 触发条件
{report.get('trigger_condition', '无')}

## 调用树分析顺序
{_bullets(report.get('analysis_order', []))}

## 函数级分析摘要
{_function_notes(report.get('function_summaries', []))}

## 语义化改名建议
{_semantic_renames(report.get('semantic_renames', []))}

## 关键证据
{_bullets(report.get('key_evidence', []))}

## 影响评估
{report.get('impact', '无')}

## 误报风险
{_risk_zh(report.get('false_positive_risk', ''))}

## 修复建议
{report.get('patch_idea', '无')}

## 最小修复方案
{report.get('minimal_fix', '无')}

## 人工复核清单
{_bullets(report.get('manual_checks', []))}
{consensus_text}"""
