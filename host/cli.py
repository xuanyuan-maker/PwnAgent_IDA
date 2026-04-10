from __future__ import annotations

"""命令行入口：用于开发调试、手工回归测试。"""

import argparse
from pathlib import Path
import sys
from uuid import uuid4

from .service import build_engine, create_manifest, get_report_paths, quick_run, run_existing_task
from .logger import get_logger

logger = get_logger("cli")


def cmd_new_task(args):
    """创建任务，不执行。"""
    root = Path(args.project_root).resolve()
    storage, _, cfg = build_engine(root)
    task_id = args.task_id or f"task-{uuid4().hex[:8]}"
    create_manifest(storage, cfg, task_id, args.binary, args.idb)
    logger.info("cli new-task: task=%s", task_id)
    print(task_id)


def cmd_quick_run(args):
    """一键创建并执行任务（给插件/脚本复用）。"""
    root = Path(args.project_root).resolve()
    result = quick_run(root, args.binary, args.idb, task_id=args.task_id)
    logger.info("cli quick-run: task=%s", result["task_id"])
    print(f"TASK_ID={result['task_id']}")
    print(f"REPORT_MD={result['report_md']}")
    print(f"REPORT_JSON={result['report_json']}")


def cmd_run(args):
    """执行或恢复一个已有任务。"""
    root = Path(args.project_root).resolve()
    manifest = run_existing_task(root, args.task_id)
    logger.info("cli run/resume: task=%s stage=%s", manifest.task_id, manifest.stage)
    print(f"{manifest.task_id}: {manifest.stage}")


def cmd_status(args):
    """查询任务阶段。"""
    root = Path(args.project_root).resolve()
    storage, _, _ = build_engine(root)
    manifest = storage.load_manifest(args.task_id)
    logger.info("cli status: task=%s stage=%s", manifest.task_id, manifest.stage)
    print(f"task={manifest.task_id} stage={manifest.stage} model={manifest.model_name}")


def cmd_report(args):
    """查看固定 reports 目录中的报告。"""
    root = Path(args.project_root).resolve()
    paths = get_report_paths(root, task_id=args.task_id)
    target = Path(paths["report_md"])
    if not target.exists():
        raise SystemExit(f"report not found: {target}")

    if args.path_only:
        print(target)
        return

    sys.stdout.write(target.read_text(encoding="utf-8"))


def build_parser():
    """构建 CLI 参数解析器。"""
    p = argparse.ArgumentParser(description="Offline linear pwn assistant host")
    p.add_argument("--project-root", default=".")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_new = sub.add_parser("new-task")
    p_new.add_argument("--task-id", default="")
    p_new.add_argument("--binary", required=True)
    p_new.add_argument("--idb", required=True)
    p_new.set_defaults(func=cmd_new_task)

    p_run = sub.add_parser("run")
    p_run.add_argument("task_id")
    p_run.set_defaults(func=cmd_run)

    p_resume = sub.add_parser("resume")
    p_resume.add_argument("task_id")
    p_resume.set_defaults(func=cmd_run)

    p_quick = sub.add_parser("quick-run")
    p_quick.add_argument("--task-id", default="")
    p_quick.add_argument("--binary", required=True)
    p_quick.add_argument("--idb", required=True)
    p_quick.set_defaults(func=cmd_quick_run)

    p_status = sub.add_parser("status")
    p_status.add_argument("task_id")
    p_status.set_defaults(func=cmd_status)

    p_report = sub.add_parser("report")
    p_report.add_argument("--task-id", default="")
    p_report.add_argument("--path-only", action="store_true")
    p_report.set_defaults(func=cmd_report)

    return p


def main():
    """CLI 主函数。"""
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
