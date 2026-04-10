from __future__ import annotations

"""服务层：把 CLI / IDA 插件共用的核心动作收敛在这里。"""

from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
from typing import Dict, Any, Iterator, Callable
from uuid import uuid4

from .config import load_config
from .storage import TaskStorage
from .model_adapter import ModelAdapter
from .ida_bridge import create_ida_bridge
from .workflow import WorkflowEngine
from .schema_validator import SimpleSchemaValidator
from .models import TaskManifest
from .logger import init_project_logger, get_logger, log_context

logger = get_logger("service")


def _new_request_id() -> str:
    """生成一次运行链路的 request_id。"""
    return f"req-{uuid4().hex[:8]}"


def _read_lock_pid(lock_path: Path) -> int | None:
    """读取锁文件中的 PID。读取失败返回 None。"""
    try:
        raw = lock_path.read_text(encoding="utf-8").strip()
        return int(raw)
    except Exception:
        return None


def _pid_alive(pid: int) -> bool:
    """检查 PID 是否存活。"""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # 无权限时保守认为进程存在
        return True


@contextmanager
def acquire_run_lock(lock_path: Path) -> Iterator[None]:
    """全局运行锁（进程级）。

    作用：保证同一时间只有一个分析流程在跑，避免本地模型并发导致资源抖动。

    细节：
    - 常规路径：使用 O_EXCL 创建锁文件。
    - 异常恢复：若锁文件存在但 PID 已不存在，自动清理“陈旧锁”并重试一次。
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = None

    def _open_lock() -> int:
        return os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)

    try:
        try:
            fd = _open_lock()
        except FileExistsError:
            stale_pid = _read_lock_pid(lock_path)
            if stale_pid is not None and not _pid_alive(stale_pid):
                # 清理陈旧锁并重试一次
                logger.warning("stale lock detected, cleanup: %s pid=%s", lock_path, stale_pid)
                lock_path.unlink(missing_ok=True)
                fd = _open_lock()
            else:
                owner = f" (pid={stale_pid})" if stale_pid is not None else ""
                logger.warning("run lock busy: %s%s", lock_path, owner)
                raise RuntimeError(f"已有分析任务在运行中（锁文件存在{owner}）：{lock_path}")

        os.write(fd, str(os.getpid()).encode("utf-8"))
        logger.info("run lock acquired: %s pid=%s", lock_path, os.getpid())
        yield
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            try:
                lock_path.unlink(missing_ok=True)
                logger.info("run lock released: %s", lock_path)
            except Exception:
                pass


def build_engine(project_root: Path, progress_callback: Callable[[Dict[str, Any]], None] | None = None):
    """构建运行所需组件：Storage / Model / IDA Bridge / Workflow。"""
    cfg = load_config(project_root / "config.yaml")
    init_project_logger(project_root, cfg)
    logger.info("build_engine: project_root=%s", project_root)
    tasks_dir = project_root / cfg.get("runtime", {}).get("tasks_dir", "tasks")
    storage = TaskStorage(tasks_dir)

    model_cfg = cfg.get("model", {})
    runtime_cfg = cfg.get("runtime", {})
    model = ModelAdapter(
        provider=model_cfg.get("provider", "ollama"),
        model_name=model_cfg.get("name", "qwen2.5-coder:14b"),
        project_root=project_root,
        base_url=model_cfg.get("base_url", "http://127.0.0.1:11434"),
        temperature=float(model_cfg.get("temperature", 0.1)),
        timeout_sec=int(runtime_cfg.get("timeout_sec", 120)),
        max_retries=int(runtime_cfg.get("max_retries", 1)),
        progress_callback=progress_callback,
        snapshot_limits={
            "functions": int(runtime_cfg.get("snapshot_max_functions", 80)),
            "strings": int(runtime_cfg.get("snapshot_max_strings", 80)),
            "imports": int(runtime_cfg.get("snapshot_max_imports", 80)),
            "dangerous_calls": int(runtime_cfg.get("snapshot_max_dangerous_calls", 24)),
        },
        evidence_limits={
            "evidence_items": int(runtime_cfg.get("evidence_max_items", 8)),
            "items_preview": int(runtime_cfg.get("evidence_max_list_items", 8)),
            "text_chars": int(runtime_cfg.get("evidence_text_chars", 700)),
        },
        round1_limits={
            "batch_size": int(runtime_cfg.get("round1_batch_size", 3)),
            "max_batches": int(runtime_cfg.get("round1_max_batches", 6)),
            "max_requests": int(runtime_cfg.get("round1_max_requests", 8)),
            "priority_top_n": int(runtime_cfg.get("round1_priority_top_n", 48)),
        },
        specific_options=model_cfg.get("specific_options", {}),
    )

    ida = create_ida_bridge()
    schema_validator = None

    agents_cfg = cfg.get("agents", {})
    scout_model = str(agents_cfg.get("scout_model", "") or "").strip() or None
    judge_model = str(agents_cfg.get("judge_model", "") or "").strip() or model_cfg.get("name", "qwen2.5-coder:14b")
    verifier_model = str(agents_cfg.get("verifier_model", "") or "").strip() or None
    verifier_on_high_risk = bool(agents_cfg.get("verifier_on_high_risk", True))

    engine = WorkflowEngine(
        storage,
        model,
        ida,
        schema_validator=schema_validator,
        agent_models={
            "scout": scout_model,
            "judge": judge_model,
            "verifier": verifier_model,
        },
        verifier_on_high_risk=verifier_on_high_risk,
        progress_callback=progress_callback,
        round2_max_suspects=int(runtime_cfg.get("round2_max_suspects", 2)),
    )
    return storage, engine, cfg


def create_manifest(storage: TaskStorage, cfg: Dict[str, Any], task_id: str, binary: str, idb: str) -> TaskManifest:
    """创建任务清单文件（task_manifest.json）。"""
    judge_model = cfg.get("agents", {}).get("judge_model") or cfg.get("model", {}).get("name", "qwen2.5-coder:14b")
    manifest = TaskManifest(
        task_id=task_id,
        binary_path=binary,
        idb_path=idb,
        model_name=judge_model,
    )
    storage.save_manifest(manifest)
    logger.info("manifest created: task=%s binary=%s idb=%s model=%s", task_id, binary, idb, judge_model)
    return manifest


def run_existing_task(
    project_root: Path,
    task_id: str,
    progress_callback: Callable[[Dict[str, Any]], None] | None = None,
) -> TaskManifest:
    """运行已存在任务（支持 resume）。"""
    storage, engine, cfg = build_engine(project_root, progress_callback=progress_callback)
    lock_file = project_root / cfg.get("runtime", {}).get("run_lock_file", "./tasks/.run.lock")
    manifest = storage.load_manifest(task_id)
    request_id = _new_request_id()
    with log_context(request_id=request_id, task_id=manifest.task_id):
        logger.info("run_existing_task start: stage=%s", manifest.stage)
        with acquire_run_lock(lock_file):
            engine.run(manifest)
        _publish_reports(project_root, cfg, manifest.task_id)
        logger.info("run_existing_task done: stage=%s", manifest.stage)
    return manifest


def _report_paths(project_root: Path, cfg: Dict[str, Any]) -> Path:
    """返回固定报告目录。"""
    reports_dir = project_root / cfg.get("runtime", {}).get("reports_dir", "reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def _write_reports_index(reports_dir: Path) -> Path:
    """根据 Markdown 报告生成简易索引页。"""
    reports = sorted(
        [p for p in reports_dir.glob("*.md") if p.name not in {"latest_report.md", "index.md"}],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    lines = ["# Reports Index", ""]

    if not reports:
        lines.append("- 暂无报告")
    else:
        for path in reports[:20]:
            created_at = datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
            lines.append(f"- `{path.stem}` | 时间=`{created_at}` | 文件=`reports/{path.name}`")

    index_path = reports_dir / "index.md"
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return index_path


def _publish_reports(project_root: Path, cfg: Dict[str, Any], task_id: str) -> Dict[str, str]:
    """将任务最终 Markdown 报告复制到固定 reports 目录，并维护 latest 入口。"""
    tasks_dir = project_root / cfg.get("runtime", {}).get("tasks_dir", "tasks")
    task_dir = tasks_dir / task_id
    report_md = task_dir / "final_report.md"
    reports_dir = _report_paths(project_root, cfg)

    published: Dict[str, str] = {}
    if report_md.exists():
        dst_md = reports_dir / f"{task_id}.md"
        shutil.copyfile(report_md, dst_md)
        shutil.copyfile(report_md, reports_dir / "latest_report.md")
        published["published_report_md"] = str(dst_md)
        published["latest_report_md"] = str(reports_dir / "latest_report.md")
        logger.info("report published: task=%s file=%s", task_id, dst_md)
    else:
        logger.warning("report missing, skip publish: task=%s expected=%s", task_id, report_md)

    published["reports_index"] = str(_write_reports_index(reports_dir))
    return published


def get_report_paths(project_root: Path, task_id: str = "") -> Dict[str, str]:
    """获取固定 reports 目录中的报告路径。"""
    cfg = load_config(project_root / "config.yaml")
    reports_dir = _report_paths(project_root, cfg)

    if task_id:
        return {
            "report_md": str(reports_dir / f"{task_id}.md"),
            "reports_index": str(reports_dir / "index.md"),
        }

    return {
        "report_md": str(reports_dir / "latest_report.md"),
        "reports_index": str(reports_dir / "index.md"),
    }


def quick_run(
    project_root: Path,
    binary: str,
    idb: str,
    task_id: str = "",
    progress_callback: Callable[[Dict[str, Any]], None] | None = None,
) -> Dict[str, str]:
    """一键任务入口（给 IDA 插件调用）。"""
    storage, engine, cfg = build_engine(project_root, progress_callback=progress_callback)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tid = task_id or f"quick-{stamp}-{uuid4().hex[:4]}"
    request_id = _new_request_id()

    with log_context(request_id=request_id, task_id=tid):
        logger.info("quick_run start: binary=%s idb=%s", binary, idb)

        lock_file = project_root / cfg.get("runtime", {}).get("run_lock_file", "./tasks/.run.lock")
        with acquire_run_lock(lock_file):
            manifest = create_manifest(storage, cfg, tid, binary, idb)
            engine.run(manifest)

        task_dir = storage.task_dir(tid)
        report_md = task_dir / "final_report.md"
        report_json = task_dir / "final_report.json"
        published = _publish_reports(project_root, cfg, tid)
        result = {
            "task_id": tid,
            "report_md": str(report_md),
            "report_json": str(report_json),
            **published,
            "request_id": request_id,
        }
        logger.info("quick_run done: stage=%s", manifest.stage)
        return result
