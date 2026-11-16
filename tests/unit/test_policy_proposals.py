"""What the system proposes at import: resource parameters (RF-35) and a template (RF-40)."""

from typing import Any

import pytest

from hindama.core.openapi_import import path_parameters, resource_parameters, suggested_policy

BEARER = [{"scheme": "bearer", "type": "http_bearer"}]


def param(name: str, kind: str | None = "string", **schema: Any) -> dict[str, Any]:
    return {"name": name, "location": "path", "required": True, "type": kind, "schema": schema}


@pytest.mark.parametrize(
    ("path", "parameters", "expected"),
    [
        ("/orders/{orderId}", [param("orderId")], [("orderId", "orders")]),
        ("/orders/{id}", [param("id")], [("id", "orders")]),
        ("/orders/{order_id}/items/{item_id}", [], [("order_id", "orders"), ("item_id", "items")]),
        ("/users/{userID}", [], [("userID", "users")]),
        ("/Pedidos/{codigo}", [param("codigo", format="uuid")], [("codigo", "pedidos")]),
        ("/invoices/{number}", [param("number", "integer")], [("number", "invoices")]),
        ("/{tenantId}/orders", [], [("tenantId", "tenant")]),  # no segment before it
        ("/files/{name}", [param("name")], []),  # a name, not an identifier
        ("/a/{x}/{y}", [], []),
        ("/orders/{id}.json", [], []),  # a mixed segment is not a parameter of its own
        ("/orders", [], []),
        ("/orders/{" + "a" * 99 + "Id}", [], []),  # longer than a ResourceParameter allows
        ("/orders/{id}/{id}", [], [("id", "orders")]),  # never twice
        ("/orders/{paid}", [], []),  # lowercase "id" at the end is a word, not a suffix
    ],
)
def test_resource_parameters(
    path: str, parameters: list[dict[str, Any]], expected: list[tuple[str, str]]
) -> None:
    proposed = resource_parameters(path, parameters)
    assert [(p["name"], p["resource_type"]) for p in proposed] == expected


def test_parameters_of_another_location_do_not_count() -> None:
    query = {"name": "page", "location": "query", "type": "integer", "schema": {}}
    assert resource_parameters("/orders/{page}", [query]) == []


@pytest.mark.parametrize(
    ("path", "security", "expected"),
    [
        ("/orders/{orderId}", [], "public"),  # no security declared
        ("/admin/users", BEARER, "admin_only"),
        ("/api/Internal/jobs/{jobId}", BEARER, "admin_only"),  # admin wins over ownership
        ("/orders/{orderId}", BEARER, "owner_only"),
        ("/orders/{orderId}/items", BEARER, "authenticated"),
        ("/orders", BEARER, "authenticated"),
        ("/me", BEARER, "authenticated"),
        ("/files/{name}", BEARER, "authenticated"),  # not a resource parameter
        ("/", BEARER, "authenticated"),
        ("/{adminId}", BEARER, "owner_only"),  # a parameter named admin is not the admin area
    ],
)
def test_suggested_policy(path: str, security: list[dict[str, str]], expected: str) -> None:
    resources = resource_parameters(path, [])
    assert suggested_policy(path, security, resources) == expected


def test_path_parameters_in_order() -> None:
    assert path_parameters("/orders/{orderId}/items/{itemId}") == ["orderId", "itemId"]
    assert path_parameters("/orders") == []
