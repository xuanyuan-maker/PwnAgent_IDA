from __future__ import annotations

"""配置解析器。

优先使用 PyYAML，如果不可用则回退到轻量解析器。
"""

from pathlib import Path
from typing import Any, Dict
import sys

from .logger import get_logger

logger = get_logger("config")


def _cast_scalar(v: str) -> Any:
    """把字符串转换成 bool/int/float/str。"""
    if v.lower() in {"true", "false"}:
        return v.lower() == "true"
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def _strip_quotes(v: str) -> str:
    """去掉首尾引号。"""
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v


def _simple_yaml_parse(text: str) -> Dict[str, Any]:
    """轻量版 YAML 解析（用于没有 PyYAML 的环境）。"""
    result: Dict[str, Any] = {}
    section: str | None = None
    list_key: str | None = None

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        # 跳过空行和注释
        if not stripped or stripped.startswith("#"):
            continue

        # section:（顶级）
        if not line.startswith(" ") and stripped.endswith(":"):
            section = stripped[:-1]
            result[section] = {}
            list_key = None
            continue

        if section is None:
            continue

        # 列表项：- xxx
        if stripped.startswith("- ") and list_key:
            item = stripped[2:].strip()
            item = _strip_quotes(item)
            result[section].setdefault(list_key, []).append(_cast_scalar(item))
            continue

        # key: value（二级）
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip()

            # 支持行尾注释
            if " #" in v:
                v = v.split(" #", 1)[0].rstrip()

            # `key:` 这种情况，后续可接 `- item`
            if v == "":
                result[section][k] = []
                list_key = k
                continue

            list_key = None
            v = _strip_quotes(v)
            result[section][k] = _cast_scalar(v)

    return result


def load_config(path: Path) -> Dict[str, Any]:
    """加载并解析配置文件。

    优先使用 PyYAML 以获得完整的 YAML 支持，包括嵌套字典。
    如果 PyYAML 不可用，则回退到轻量解析器。
    """
    try:
        import yaml
        with open(path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        logger.info("config loaded with PyYAML: %s", path)
    except ImportError:
        logger.warning("PyYAML not available, using simple parser")
        cfg = _simple_yaml_parse(path.read_text(encoding="utf-8"))
        logger.info("config loaded with simple parser: %s", path)
    except Exception as e:
        logger.error("YAML parsing failed: %s, falling back to simple parser", e)
        cfg = _simple_yaml_parse(path.read_text(encoding="utf-8"))
    
    return cfg or {}
