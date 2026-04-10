"""
pwn-agent 的 IDA 插件入口（V1）。

设计目标：
1) 通过热键在 IDA 内一键触发分析（默认 Ctrl+Shift+A）
2) 后端流程在后台线程执行，不阻塞 IDA 主界面
3) 增加“防重入锁”，避免用户连按热键导致多任务并发
4) 增加“加载哨兵文件”，便于外部脚本检测插件是否真正加载成功

可选环境变量：
- PWN_AGENT_ROOT: pwn-agent 项目根目录
- PWN_AGENT_AUTORUN: 置为 1 时，插件加载后自动触发一次分析（供自动化测试）
- PWN_AGENT_SENTINEL: 插件加载哨兵文件路径（默认 /tmp/pwn-agent.plugin.loaded）
- PWN_AGENT_TEST_MARKER: 调试标记文件（记录 loaded/activate/done/error）
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

import idaapi
import ida_kernwin
import ida_loader
import ida_nalt


PLUGIN_VERSION = "0.1.1"

ACTION_NAME = "pwn_agent:run_analysis"
ACTION_LABEL = "运行 PWN-Agent 分析"
ACTION_HOTKEY = "Ctrl+Shift+A"


_RUNNING_LOCK = threading.Lock()
_RUNNING = False


def _set_running(v: bool) -> None:
    global _RUNNING
    with _RUNNING_LOCK:
        _RUNNING = v


def _is_running() -> bool:
    with _RUNNING_LOCK:
        return _RUNNING


def _is_project_root(p: Path) -> bool:
    return (p / "host").is_dir() and (p / "config.yaml").exists()


def _project_root() -> Path:
    env = os.getenv("PWN_AGENT_ROOT", "").strip()
    if env:
        cand = Path(env).expanduser().resolve()
        if _is_project_root(cand):
            return cand

    resolved = Path(__file__).resolve()
    for cand in [resolved.parent.parent, resolved.parent, Path.cwd()]:
        if _is_project_root(cand):
            return cand

    cur = Path(__file__).parent
    for _ in range(6):
        if _is_project_root(cur):
            return cur
        cur = cur.parent

    return resolved.parent.parent


def _binary_path() -> str:
    return ida_nalt.get_input_file_path() or ""


def _idb_path() -> str:
    try:
        path_type = getattr(ida_loader, "PATH_TYPE_IDB", None)
        if path_type is not None:
            p = ida_loader.get_path(path_type)
            if p:
                return p
    except Exception:
        pass
    return ""


def _write_test_marker(event: str, detail: str = "") -> None:
    marker = os.getenv("PWN_AGENT_TEST_MARKER", "").strip()
    if not marker:
        return
    try:
        ts = datetime.now().isoformat(timespec="seconds")
        line = f"{ts} [{event}] {detail}\n"
        p = Path(marker).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def _write_sentinel(status: str) -> None:
    sentinel = os.getenv("PWN_AGENT_SENTINEL", "/tmp/pwn-agent.plugin.loaded").strip()
    if not sentinel:
        return
    try:
        p = Path(sentinel).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "status": status,
            "plugin": "pwn-agent",
            "version": PLUGIN_VERSION,
            "hotkey": ACTION_HOTKEY,
            "file": str(Path(__file__).resolve()),
        }
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _read_final_summary(report_json_path: str) -> str:
    try:
        report = json.loads(Path(report_json_path).read_text(encoding="utf-8"))
    except Exception:
        return "（读取 final_report.json 失败）"

    vuln = report.get("suspected_vulnerability_type", "未知")
    funcs = report.get("vulnerable_functions", [])
    func_line = "、".join([str(x) for x in funcs[:3]]) if isinstance(funcs, list) and funcs else "未知"
    risk = report.get("false_positive_risk", "未知")
    return f"疑似漏洞：{vuln}\n可疑函数：{func_line}\n误报风险：{risk}"


def _ui_info(text: str) -> None:
    idaapi.execute_sync(lambda: ida_kernwin.info(text), idaapi.MFF_WRITE)


def _ui_warn(text: str) -> None:
    idaapi.execute_sync(lambda: ida_kernwin.warning(text), idaapi.MFF_WRITE)


def _friendly_error_text(err: Exception) -> str:
    s = str(err)
    if "锁文件存在" in s:
        return "已有分析任务在运行中，请等待当前任务完成后再试。"
    if "IDA runtime unavailable" in s:
        return "IDA 运行时不可用：请确认在 IDA 内触发插件，而非外部 Python 环境。"
    if "Model output is not valid JSON object" in s:
        return "模型输出不是合法 JSON。建议降低温度或缩短提示词后重试。"
    if "Ollama request failed" in s:
        return "模型请求失败：请检查 Ollama 服务与模型是否已启动。"
    if "SchemaValidationError" in s or "missing required field" in s:
        return "模型输出字段不完整（Schema 校验失败），请重试或更换模型。"
    return s


class PwnAgentRunHandler(ida_kernwin.action_handler_t):
    def _run_analysis_bg(self, root: Path, binary: str, idb: str):
        try:
            root_str = str(root)
            if root_str not in sys.path:
                sys.path.insert(0, root_str)
            from host.service import quick_run
        except ModuleNotFoundError as e:
            _write_test_marker("error", f"import host.service failed: {e}; root={root}")
            _ui_warn(
                "导入后端失败：{err}\n"
                "project_root={root}\n"
                "请检查 PWN_AGENT_ROOT 是否指向项目根目录。".format(err=e, root=root)
            )
            _set_running(False)
            return
        except Exception as e:
            _write_test_marker("error", f"import host.service failed: {e}")
            _ui_warn(f"导入后端失败：{e}")
            _set_running(False)
            return

        ida_kernwin.msg("[pwn-agent] 分析已在后台启动，完成后会弹窗提示。\n")

        try:
            result = quick_run(root, binary=binary, idb=idb)
            report_md = result.get("report_md", "")
            report_json = result.get("report_json", "")
            latest_report_md = result.get("latest_report_md", "")
            reports_index = result.get("reports_index", "")
            task_id = result.get("task_id", "")
            summary = _read_final_summary(report_json) if report_json else "（无最终报告）"

            _write_test_marker("done", f"task={task_id} md={report_md}")
            ida_kernwin.msg(
                f"[pwn-agent] 分析完成 task={task_id} report={report_md} latest={latest_report_md or report_md}\n"
            )
            _ui_info("分析完成")
        except Exception as e:
            msg = _friendly_error_text(e)
            _write_test_marker("error", f"backend exception: {e}")
            _ui_warn(f"分析失败：\n{msg}")
        finally:
            _set_running(False)

    def activate(self, ctx):
        if _is_running():
            ida_kernwin.warning("分析任务仍在运行中，请稍候。")
            return 1

        root = _project_root()
        _write_test_marker("activate", f"root={root}")

        binary = _binary_path()
        idb = _idb_path()

        if not binary:
            ida_kernwin.warning("未获取到 binary 路径。")
            return 1
        if not idb:
            ida_kernwin.warning("未获取到 IDB 路径，请先保存数据库。")
            return 1

        _set_running(True)
        t = threading.Thread(target=self._run_analysis_bg, args=(root, binary, idb), daemon=True)
        t.start()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class PwnAgentPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "运行离线 pwn-agent 分析"
    help = "热键触发完整分析流程并输出中文结论"
    wanted_name = "pwn-agent"
    wanted_hotkey = ACTION_HOTKEY

    def init(self):
        desc = ida_kernwin.action_desc_t(
            ACTION_NAME,
            ACTION_LABEL,
            PwnAgentRunHandler(),
            ACTION_HOTKEY,
            "运行 pwn-agent 线性分析",
            0,
        )
        ok = ida_kernwin.register_action(desc)
        if ok:
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_NAME, ida_kernwin.SETMENU_APP)
            _write_test_marker("loaded", f"version={PLUGIN_VERSION} hotkey={ACTION_HOTKEY}")
            _write_sentinel("loaded")
            ida_kernwin.msg(f"[pwn-agent] loaded v{PLUGIN_VERSION}. Hotkey: {ACTION_HOTKEY}\n")
            print(f"[pwn-agent] loaded v{PLUGIN_VERSION}. Hotkey: {ACTION_HOTKEY}")

            if os.getenv("PWN_AGENT_AUTORUN", "").strip() == "1":
                _write_test_marker("autorun", "start")
                PwnAgentRunHandler().activate(None)

            return idaapi.PLUGIN_KEEP

        _write_test_marker("error", "failed to register action")
        _write_sentinel("register_failed")
        print("[pwn-agent] failed to register action")
        return idaapi.PLUGIN_SKIP

    def term(self):
        try:
            ida_kernwin.detach_action_from_menu("Edit/Plugins/", ACTION_NAME)
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_NAME)

    def run(self, arg):
        PwnAgentRunHandler().activate(None)


def PLUGIN_ENTRY():
    return PwnAgentPlugin()
