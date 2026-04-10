from __future__ import annotations

"""IDA 证据桥门面层（兼容旧导入路径）。

重构后结构：
- 接口层：`ida_bridge_interface.py`
- 实现层：`ida_bridge_impl.py`

本文件保留 `IDABridge` 名称，避免现有调用代码大规模改动。
"""

from .ida_bridge_interface import IDAEvidenceBridge
from .ida_bridge_impl import IDABridgeImpl


def create_ida_bridge() -> IDAEvidenceBridge:
    """创建真实 IDA 桥接实现。"""
    return IDABridgeImpl()


class IDABridge(IDABridgeImpl):
    """兼容别名：旧代码仍可 `from .ida_bridge import IDABridge`。"""


__all__ = ["IDAEvidenceBridge", "IDABridge", "IDABridgeImpl", "create_ida_bridge"]
