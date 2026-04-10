from __future__ import annotations

"""轻量 JSON Schema 校验器（离线无第三方依赖）。

支持子集：
- type: object / array / string
- required
- properties
- items
"""

import json
from pathlib import Path
from typing import Any, Dict, List


class SchemaValidationError(ValueError):
    """Schema 校验失败异常。"""


class SimpleSchemaValidator:
    """按文件名加载 schema，并校验数据对象。"""

    def __init__(self, schema_dir: Path):
        self.schema_dir = schema_dir
        self._schemas: Dict[str, Dict[str, Any]] = {}

    def validate_named(self, schema_filename: str, data: Dict[str, Any]) -> None:
        """校验 data 是否符合指定 schema。"""
        schema = self._load_schema(schema_filename)
        errors = self._validate(schema, data, path="$")
        if errors:
            raise SchemaValidationError("; ".join(errors))

    def _load_schema(self, schema_filename: str) -> Dict[str, Any]:
        """按需加载 schema，并做内存缓存。"""
        if schema_filename not in self._schemas:
            p = self.schema_dir / schema_filename
            self._schemas[schema_filename] = json.loads(p.read_text(encoding="utf-8"))
        return self._schemas[schema_filename]

    def _validate(self, schema: Dict[str, Any], value: Any, path: str) -> List[str]:
        """递归校验对象。"""
        errors: List[str] = []
        expected_type = schema.get("type")

        if expected_type == "object":
            if not isinstance(value, dict):
                return [f"{path}: expected object, got {type(value).__name__}"]

            for req in schema.get("required", []):
                if req not in value:
                    errors.append(f"{path}.{req}: missing required field")

            props = schema.get("properties", {})
            for k, v in value.items():
                if k in props:
                    errors.extend(self._validate(props[k], v, f"{path}.{k}"))

        elif expected_type == "array":
            if not isinstance(value, list):
                return [f"{path}: expected array, got {type(value).__name__}"]
            item_schema = schema.get("items")
            if isinstance(item_schema, dict):
                for idx, item in enumerate(value):
                    errors.extend(self._validate(item_schema, item, f"{path}[{idx}]"))

        elif expected_type == "string":
            if not isinstance(value, str):
                return [f"{path}: expected string, got {type(value).__name__}"]

        return errors
