"""The API implements hindama-docs/03-api/openapi.yaml (ADR-016: the contract rules).

Every operation the app exposes must exist in the contract and match it: operationId, security,
success status codes, parameters, request body and success response schemas. Operations of the
contract that are not implemented yet only produce a warning, so the contract can lead the code.

The contract is read from HINDAMA_CONTRACT_PATH, by default the sibling hindama-docs checkout.
"""

import os
import warnings
from pathlib import Path
from typing import Any

import pytest
import yaml

from hindama.main import create_app
from tests.conftest import make_settings

DEFAULT_CONTRACT = Path(__file__).parents[3] / "hindama-docs" / "03-api" / "openapi.yaml"
CONTRACT_PATH = Path(os.environ.get("HINDAMA_CONTRACT_PATH", DEFAULT_CONTRACT))
HTTP_METHODS = {"get", "put", "post", "delete", "patch"}

pytestmark = pytest.mark.skipif(
    not CONTRACT_PATH.is_file(), reason=f"contract not found at {CONTRACT_PATH}"
)

# Schema keywords that define what goes on the wire. Titles, descriptions, examples and defaults
# are documentation and may differ.
COMPARED_KEYWORDS = {
    "type",
    "enum",
    "format",
    "required",
    "properties",
    "items",
    "additionalProperties",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "uniqueItems",
    "oneOf",
    "anyOf",
}


Operation = tuple[str, str]  # (METHOD, path)


def operations(document: dict[str, Any]) -> dict[Operation, dict[str, Any]]:
    return {
        (method.upper(), path): operation
        for path, item in document.get("paths", {}).items()
        for method, operation in item.items()
        if method in HTTP_METHODS
    }


class Resolver:
    """Turns a schema of one document into a comparable form, following its `$ref`s."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document

    def ref(self, node: dict[str, Any]) -> dict[str, Any]:
        while "$ref" in node:
            target: Any = self.document
            for part in node["$ref"].removeprefix("#/").split("/"):
                target = target[part]
            node = target
        return node

    def schema(self, node: dict[str, Any], depth: int = 0) -> Any:
        assert depth < 30, "schema too deep (recursive $ref?)"
        node = self.ref(node)
        if "const" in node:  # Pydantic writes Literal["ok"] as const; the contract as enum
            node = {**node, "enum": [node["const"]]}
        nullable, node = self.split_null(node)
        result: dict[str, Any] = {"nullable": nullable}
        for keyword in COMPARED_KEYWORDS & node.keys():
            value = node[keyword]
            if keyword == "properties":
                value = {name: self.schema(sub, depth + 1) for name, sub in value.items()}
            elif keyword == "items" or (
                keyword == "additionalProperties" and isinstance(value, dict)
            ):
                value = self.schema(value, depth + 1)
            elif keyword in ("oneOf", "anyOf"):
                value = sorted((self.schema(sub, depth + 1) for sub in value), key=repr)
            elif keyword in ("required", "enum"):
                value = sorted(value, key=repr)
            result[keyword] = value
        return result

    def split_null(self, node: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """`type: [x, 'null']` and `anyOf: [x, {type: null}]` both mean "x or null"."""
        kind = node.get("type")
        if isinstance(kind, list) and "null" in kind:
            rest = [k for k in kind if k != "null"]
            return True, {**node, "type": rest[0] if len(rest) == 1 else rest}
        for keyword in ("anyOf", "oneOf"):
            options = node.get(keyword)
            if options and any(self.ref(o).get("type") == "null" for o in options):
                rest = [o for o in options if self.ref(o).get("type") != "null"]
                others = {k: v for k, v in node.items() if k != keyword}
                if len(rest) == 1:
                    return True, {**others, **self.ref(rest[0])}
                return True, {**others, keyword: rest}
        return False, node

    def security(self, operation: dict[str, Any]) -> list[str]:
        requirements = operation.get("security", self.document.get("security", []))
        return sorted(name for requirement in requirements for name in requirement)

    def parameters(self, operation: dict[str, Any]) -> dict[tuple[str, str], Any]:
        return {
            (p["in"], p["name"]): (p.get("required", False), self.schema(p.get("schema", {})))
            for p in map(self.ref, operation.get("parameters", []))
            # Headers handled by the platform for every request, not per operation.
            if not (p["in"] == "header" and p["name"].lower() in ("authorization", "x-request-id"))
        }

    def body(self, operation: dict[str, Any]) -> Any:
        body = operation.get("requestBody")
        if body is None:
            return None
        body = self.ref(body)
        return {
            "required": body.get("required", False),
            "content": {
                media: self.schema(content.get("schema", {}))
                for media, content in body.get("content", {}).items()
            },
        }

    def success(self, operation: dict[str, Any]) -> dict[str, Any]:
        """2xx responses only: FastAPI adds its own 422, and errors follow convenciones.md."""
        result = {}
        for status, response in operation.get("responses", {}).items():
            if str(status).startswith("2"):
                response = self.ref(response)
                result[str(status)] = {
                    media: self.schema(content.get("schema", {}))
                    for media, content in response.get("content", {}).items()
                }
        return result


@pytest.fixture(scope="module")
def contract() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))
    return document


@pytest.fixture(scope="module")
def implemented() -> dict[str, Any]:
    settings = make_settings("postgresql+asyncpg://test:test@localhost:1/unused")
    return create_app(settings).openapi()


def implemented_operations(implemented: dict[str, Any]) -> list[Operation]:
    return sorted(operations(implemented))


def test_version_matches_the_contract(
    contract: dict[str, Any], implemented: dict[str, Any]
) -> None:
    assert implemented["info"]["version"] == contract["info"]["version"]


def test_every_implemented_operation_is_in_the_contract(
    contract: dict[str, Any], implemented: dict[str, Any]
) -> None:
    undocumented = operations(implemented).keys() - operations(contract).keys()
    assert not undocumented, f"Endpoints fuera del contrato: {sorted(undocumented)}"

    pending = sorted(operations(contract).keys() - operations(implemented).keys())
    if pending:
        listed = ", ".join(f"{method} {path}" for method, path in pending)
        warnings.warn(
            f"{len(pending)} operaciones del contrato sin implementar: {listed}", stacklevel=1
        )


def test_implemented_operations_match_the_contract(
    contract: dict[str, Any], implemented: dict[str, Any]
) -> None:
    expected_ops, actual_ops = operations(contract), operations(implemented)
    expected, actual = Resolver(contract), Resolver(implemented)
    mismatches: list[str] = []

    for key in sorted(actual_ops.keys() & expected_ops.keys()):
        want, have = expected_ops[key], actual_ops[key]
        checks = {
            "operationId": (want.get("operationId"), have.get("operationId")),
            "security": (expected.security(want), actual.security(have)),
            "parameters": (expected.parameters(want), actual.parameters(have)),
            "requestBody": (expected.body(want), actual.body(have)),
            "2xx responses": (expected.success(want), actual.success(have)),
        }
        for name, (contract_value, app_value) in checks.items():
            if contract_value != app_value:
                mismatches.append(
                    f"{key[0]} {key[1]} {name}:\n"
                    f"  contrato: {contract_value}\n  app:      {app_value}"
                )

    assert not mismatches, "\n".join(mismatches)
