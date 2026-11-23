"""Which operations are listings, and which identifiers their answers carry (RF-36)."""

import json
from typing import Any

import pytest

from hindama.core.resource_discovery import (
    array_location,
    identifiers,
    needs_document,
    resource_type,
)

DOCUMENT = {
    "components": {
        "schemas": {
            "Orders": {"type": "array", "items": {"$ref": "#/components/schemas/Order"}},
            "Order": {"type": "object", "properties": {"id": {"type": "integer"}}},
            "Page": {
                "type": "object",
                "properties": {"data": {"$ref": "#/components/schemas/Orders"}},
            },
        }
    }
}
ARRAY = {"type": "array", "items": {"type": "object"}}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/orders", "orders"),
        ("/v2/users/", "users"),
        ("/", None),
        ("", None),
        ("/" + "x" * 101, None),
        ("/con\ttab", None),
    ],
)
def test_resource_type(path: str, expected: str | None) -> None:
    assert resource_type(path) == expected


@pytest.mark.parametrize(
    ("responses", "expected"),
    [
        ({"200": {"application/json": ARRAY}}, (True, None)),
        ({"200": {"application/json": {"type": ["array", "null"]}}}, (True, None)),
        ({"2XX": {"application/vnd.api+json": ARRAY}}, (True, None)),
        ({"200": {"application/json; charset=utf-8": ARRAY}}, (True, None)),
        (
            {"200": {"application/json": {"type": "object", "properties": {"items": ARRAY}}}},
            (True, "items"),
        ),
        ({"200": {"application/json": {"$ref": "#/components/schemas/Orders"}}}, (True, None)),
        ({"200": {"application/json": {"$ref": "#/components/schemas/Page"}}}, (True, "data")),
        ({"200": {"application/json": {"$ref": "#/components/schemas/Order"}}}, (False, None)),
        ({"200": {"application/json": {"$ref": "#/components/schemas/Nada"}}}, (False, None)),
        ({"200": {"text/csv": ARRAY}}, (False, None)),
        ({"404": {"application/json": ARRAY}}, (False, None)),
        ({"200": {}}, (False, None)),
        ({"200": {"application/json": None}}, (False, None)),
        ({}, (False, None)),
    ],
)
def test_array_location(responses: dict[str, Any], expected: tuple[bool, str | None]) -> None:
    assert array_location(responses, DOCUMENT) == expected


def test_a_reference_needs_the_document() -> None:
    assert needs_document({"200": {"application/json": {"$ref": "#/x"}}})
    assert not needs_document({"200": {"application/json": ARRAY}})
    assert array_location({"200": {"application/json": {"$ref": "#/x"}}}, None) == (False, None)


@pytest.mark.parametrize(
    ("body", "field", "expected"),
    [
        ([{"id": 1}, {"id": "a-2"}, {"id": 1}], None, ["1", "a-2"]),
        ({"items": [{"id": 3}], "other": [{"id": 4}]}, "items", ["3"]),
        ({"total": 1, "results": [{"id": 5}]}, "items", ["5"]),  # the first array it has
        ({"total": 1, "results": [{"id": 5}]}, None, ["5"]),
        ([{"id": True}, {"id": None}, {"id": 1.5}, {"id": ""}, {"uuid": "x"}, 7], None, []),
        ([{"id": "x" * 501}, {"id": "a\nb"}, {"id": "x" * 500}], None, ["x" * 500]),
        ({"total": 0}, "items", []),
        ("texto", None, []),
    ],
)
def test_identifiers(body: Any, field: str | None, expected: list[str]) -> None:
    assert identifiers(json.dumps(body).encode(), field) == expected


def test_an_answer_that_is_not_json() -> None:
    assert identifiers(b"<html>", None) == []
    assert identifiers(b"[" * 100_000, None) == []
