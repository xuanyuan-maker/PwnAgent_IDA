from __future__ import annotations

"""IDA 证据桥接口层。"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class IDAEvidenceBridge(ABC):
    """IDA 证据桥抽象接口。

    约定：
    - `base_snapshot` 返回基础静态快照
    - `collect_round2_evidence` 根据请求返回二次证据
    """

    @abstractmethod
    def base_snapshot(self, binary_path: str) -> Dict[str, Any]:
        """采集基础快照（BASE_SNAPSHOT 阶段）。"""
        raise NotImplementedError

    @abstractmethod
    def collect_round2_evidence(self, requests: List[Dict[str, str]]) -> Dict[str, Any]:
        """采集二次证据（ROUND2_EVIDENCE 阶段）。"""
        raise NotImplementedError
