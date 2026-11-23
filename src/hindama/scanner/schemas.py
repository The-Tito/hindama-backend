"""The contract's schemas as the scanner reads them (API3, API4, SQL injection).

The import stores each operation's schemas inline, or as a `$ref` into the original document when
they live in a shared component (core/openapi_import.py). `deref` follows those references in the
document kept with the contract version. Nothing here trusts the document: a broken or cyclic
reference just resolves to nothing.
"""

from collections.abc import Mapping
from typing import Any

MAX_DEPTH = 20


def pointer(root: Any, ref: str) -> Any:
    """`#/a/b~1c` in `root`, or None."""
    if not ref.startswith("#"):
        return None
    node = root
    for raw in ref[1:].split("/")[1:] if ref != "#" else []:
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node


def deref(root: Any, schema: Any) -> Any:
    """The schema itself, following top-level `$ref`s (never more than MAX_DEPTH)."""
    for _ in range(MAX_DEPTH):
        if not (isinstance(schema, dict) and isinstance(schema.get("$ref"), str)):
            return schema
        schema = pointer(root, schema["$ref"])
    return None


def schema_type(root: Any, schema: Any) -> str | None:
    """`object`, `array`, `string`... The first non-null one of a 3.1 list."""
    resolved = deref(root, schema)
    if not isinstance(resolved, dict):
        return None
    kind = resolved.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if isinstance(k, str) and k != "null"), None)
    if kind is None and isinstance(resolved.get("properties"), dict):
        return "object"
    return kind if isinstance(kind, str) else None


def is_json(media: str) -> bool:
    media = media.split(";")[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def json_schema(content: Mapping[str, Any] | None) -> Any:
    """The schema of the first JSON media type of a `{media: schema}` map."""
    for media, schema in (content or {}).items():
        if is_json(media) and schema is not None:
            return schema
    return None
