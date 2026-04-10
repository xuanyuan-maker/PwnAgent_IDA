"""pwn-agent 宿主层包。

重构说明：
- IDA 证据桥已拆分为接口层与实现层：
  - `ida_bridge_interface.py`
  - `ida_bridge_impl.py`
- `ida_bridge.py` 保留兼容门面。
"""
