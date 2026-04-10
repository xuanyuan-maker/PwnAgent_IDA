from __future__ import annotations

"""任务文件存储层。"""

from pathlib import Path
import json
from typing import Any, Dict

from .models import TaskManifest
from .logger import get_logger

logger = get_logger("storage")


class TaskStorage:
    """封装任务目录与 JSON 文件读写。"""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def task_dir(self, task_id: str) -> Path:
        """返回任务目录，不存在则创建。"""
        d = self.root / task_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_json(self, task_id: str, name: str, data: Dict[str, Any]) -> Path:
        """保存一个 JSON 文件到任务目录。"""
        p = self.task_dir(task_id) / name
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.debug("save_json: task=%s file=%s", task_id, p)
        return p

    def load_json(self, task_id: str, name: str) -> Dict[str, Any]:
        """读取任务目录中的 JSON 文件。"""
        p = self.task_dir(task_id) / name
        logger.debug("load_json: task=%s file=%s", task_id, p)
        return json.loads(p.read_text(encoding="utf-8"))

    def save_manifest(self, manifest: TaskManifest) -> Path:
        """保存任务清单。"""
        return self.save_json(manifest.task_id, "task_manifest.json", manifest.to_dict())

    def load_manifest(self, task_id: str) -> TaskManifest:
        """读取任务清单。"""
        p = self.task_dir(task_id) / "task_manifest.json"
        return TaskManifest.from_file(p)
