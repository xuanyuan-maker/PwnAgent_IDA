from __future__ import annotations

"""任务元数据模型。"""

from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict
import json


class Stage(str, Enum):
    """线性状态机阶段定义。"""

    INIT = "INIT"
    BASE_SNAPSHOT = "BASE_SNAPSHOT"
    ROUND1_ANALYSIS = "ROUND1_ANALYSIS"
    ROUND2_EVIDENCE = "ROUND2_EVIDENCE"
    FINAL_ANALYSIS = "FINAL_ANALYSIS"
    EXPORT = "EXPORT"
    DONE = "DONE"


@dataclass
class TaskManifest:
    """单任务清单（持久化到 task_manifest.json）。"""

    task_id: str
    binary_path: str
    idb_path: str
    model_name: str
    stage: str = Stage.INIT.value

    def to_dict(self) -> Dict[str, Any]:
        """转字典，便于 JSON 序列化。"""
        return asdict(self)

    @classmethod
    def from_file(cls, path: Path) -> "TaskManifest":
        """从 JSON 文件恢复任务清单。"""
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)
