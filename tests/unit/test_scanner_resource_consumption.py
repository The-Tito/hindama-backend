"""API4 without a network: which operations it picks, its bodies, and the contract's schemas."""

import json
import uuid
from typing import Any

from hindama.core.identity_probe import LoginRequest
from hindama.models.enums import AuthType, HttpMethod, IdentityRole, Policy
from hindama.scanner.context import Actor, RunContext, Target
from hindama.scanner.modules.resource_consumption import (
    _array_of,
    body_target,
    burst_target,
)
from hindama.scanner.schemas import deref, json_schema, pointer, schema_type

DOCUMENT: dict[str, Any] = {
    "components": {
        "schemas": {
            "Ticket": {"type": "object", "properties": {"title": {"type": "string"}}},
            "Alias": {"$ref": "#/components/schemas/Ticket"},
            "Loop": {"$ref": "#/components/schemas/Loop"},
            "List": {"type": "array", "items": {"type": "string"}},
            "a/b": {"type": ["string", "null"]},
        }
    }
}


def target(method: HttpMethod, path: str, policy: Policy | None, schema: Any = None) -> Target:
    return Target(uuid.uuid4(), method, path, policy, (), request_schema=schema)


def context(*targets: Target, login: str | None = None) -> RunContext:
    actor = Actor(uuid.uuid4(), "ana", IdentityRole.USER, AuthType.LOGIN, None)
    if login is not None:
        actor.login = LoginRequest(url=login, username_field="u", password_field="p")
    return RunContext(
        uuid.uuid4(), uuid.uuid4(), "https://api.x", "api.x", list(targets), [actor], {}, DOCUMENT
    )


def test_references_are_followed_without_trusting_the_document() -> None:
    assert schema_type(DOCUMENT, {"$ref": "#/components/schemas/Alias"}) == "object"
    assert schema_type(DOCUMENT, {"$ref": "#/components/schemas/List"}) == "array"
    assert schema_type(DOCUMENT, {"$ref": "#/components/schemas/a~1b"}) == "string"
    assert deref(DOCUMENT, {"$ref": "#/components/schemas/Loop"}) is None  # a cycle
    assert deref(DOCUMENT, {"$ref": "#/nowhere"}) is None
    assert deref(DOCUMENT, {"$ref": "https://evil.example/schema"}) is None  # never fetched
    assert pointer(DOCUMENT, "#/components/schemas/List/items/type") == "string"
    assert schema_type(None, {"properties": {"a": {}}}) == "object"


def test_only_json_bodies_count() -> None:
    assert json_schema({"text/plain": {"type": "string"}}) is None
    assert json_schema({"application/problem+json; charset=utf-8": {"type": "object"}}) == {
        "type": "object"
    }


def test_the_burst_prefers_a_public_or_authenticated_operation() -> None:
    admin = target(HttpMethod.GET, "/admin/stats", Policy.ADMIN_ONLY)
    item = target(HttpMethod.GET, "/items/{id}", Policy.PUBLIC)
    public = target(HttpMethod.GET, "/catalog", Policy.PUBLIC)

    assert burst_target(context(admin, item, public)) == public
    assert burst_target(context(admin, item)) == admin  # any GET without path parameters
    assert burst_target(context(item)) is None


def test_the_body_goes_to_an_object_body_that_is_not_a_login() -> None:
    login = target(HttpMethod.POST, "/auth/login", Policy.PUBLIC, {"type": "object"})
    listed = target(HttpMethod.POST, "/bulk", None, {"$ref": "#/components/schemas/List"})
    nested = target(HttpMethod.PUT, "/tickets/{id}", None, {"type": "object"})
    ticket = target(HttpMethod.POST, "/tickets", None, {"$ref": "#/components/schemas/Alias"})

    chosen = body_target(context(login, listed, nested, ticket, login="https://api.x/auth/login"))

    assert chosen == ticket
    assert body_target(context(listed, nested)) is None


def test_each_body_is_a_json_array_of_the_exact_size() -> None:
    for size in (64 * 1024, 1024 * 1024):
        body = _array_of(size)
        assert len(body) == size
        assert isinstance(json.loads(body), list)
