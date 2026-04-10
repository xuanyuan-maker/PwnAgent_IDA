from __future__ import annotations

"""项目级日志初始化与获取。

目标：
- 在整个项目内统一使用 `logging` 输出
- 同时输出到控制台与文件（logs/pwn-agent.log）
- 可重复调用初始化函数，不重复挂 handler
"""

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Dict, Iterator


_ROOT_LOGGER_NAME = "pwn_agent"

# 全链路上下文字段：用于在日志中串起一次请求/任务。
_REQUEST_ID: ContextVar[str] = ContextVar("pwn_agent_request_id", default="-")
_TASK_ID: ContextVar[str] = ContextVar("pwn_agent_task_id", default="-")


class _ContextFilter(logging.Filter):
    """将 request_id/task_id 注入每条日志记录。"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _REQUEST_ID.get()
        record.task_id = _TASK_ID.get()
        return True


@contextmanager
def log_context(*, request_id: str | None = None, task_id: str | None = None) -> Iterator[None]:
    """临时设置日志上下文（可嵌套）。"""
    tok_req = _REQUEST_ID.set(request_id or _REQUEST_ID.get())
    tok_task = _TASK_ID.set(task_id or _TASK_ID.get())
    try:
        yield
    finally:
        _REQUEST_ID.reset(tok_req)
        _TASK_ID.reset(tok_task)


def init_project_logger(project_root: Path, cfg: Dict[str, Any]) -> logging.Logger:
    """初始化项目日志器（幂等）。"""
    runtime_cfg = cfg.get("runtime", {}) if isinstance(cfg, dict) else {}
    level_name = str(runtime_cfg.get("log_level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    logs_dir = project_root / runtime_cfg.get("logs_dir", "logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "pwn-agent.log"

    logger = logging.getLogger(_ROOT_LOGGER_NAME)
    logger.setLevel(level)

    if not getattr(logger, "_configured", False):
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | req=%(request_id)s | task=%(task_id)s | %(message)s"
        )
        ctx_filter = _ContextFilter()

        # 文件日志（全量保留）
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        fh.addFilter(ctx_filter)

        # 控制台日志（便于直接观察）
        sh = logging.StreamHandler()
        sh.setLevel(level)
        sh.setFormatter(fmt)
        sh.addFilter(ctx_filter)

        logger.addHandler(fh)
        logger.addHandler(sh)
        logger.propagate = False
        logger._configured = True  # type: ignore[attr-defined]
    else:
        # 日志级别支持热更新
        for h in logger.handlers:
            h.setLevel(level)

    logger.info("logger initialized: level=%s file=%s", level_name, log_file)
    return logger


def current_request_id() -> str:
    """读取当前日志上下文 request_id。"""
    return _REQUEST_ID.get()


def current_task_id() -> str:
    """读取当前日志上下文 task_id。"""
    return _TASK_ID.get()


def get_logger(name: str) -> logging.Logger:
    """返回项目子日志器，例如 pwn_agent.workflow。"""
    if not name:
        return logging.getLogger(_ROOT_LOGGER_NAME)
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")
