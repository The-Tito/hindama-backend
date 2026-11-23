"""API3 without a network: what it compares, what it sends and what it deletes (RF-58, RN-06)."""

import uuid
from typing import Any

from hindama.models.enums import AuthType, HttpMethod, IdentityRole, Policy
from hindama.scanner.context import Actor, RunContext, Target
from hindama.scanner.evidence import Exchange
from hindama.scanner.modules.property_access import (
    PropertyAccess,
    accepted_fields,
    delete_for,
    delete_location,
    listed_properties,
    protected_fields,
    sample_body,
    undeclared_fields,
)

DOCUMENT: dict[str, Any] = {
    "components": {
        "schemas": {
            "NoteIn": {
                "type": "object",
                "required": ["text", "kind"],
                "properties": {
                    "text": {"type": "string"},
                    "kind": {"type": "string", "enum": ["memo", "todo"]},
                    "due": {"type": "string", "format": "date"},
                    "secret": {"type": "boolean", "readOnly": True},
                },
            },
            "Note": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "text": {"type": "string"},
                    "owner": {"type": "string"},
                    "score": {"type": "integer"},
                },
            },
        }
    }
}
NOTE_IN = {"$ref": "#/components/schemas/NoteIn"}
NOTE = {"$ref": "#/components/schemas/Note"}
ANA = Actor(uuid.uuid4(), "ana", IdentityRole.USER, AuthType.BEARER, None)


def target(method: HttpMethod, path: str, request: Any = None, response: Any = None) -> Target:
    return Target(uuid.uuid4(), method, path, Policy.AUTHENTICATED, (), (), request, response)


def context(*targets: Target) -> RunContext:
    return RunContext(
        uuid.uuid4(), uuid.uuid4(), "https://api.x", "api.x", list(targets), [ANA], {}, DOCUMENT
    )


CREATE = target(HttpMethod.POST, "/notes", NOTE_IN, NOTE)
DELETE = target(HttpMethod.DELETE, "/notes/{note_id}")


def test_only_a_creation_the_contract_can_delete_is_written() -> None:
    deeper = target(HttpMethod.DELETE, "/notes/{note_id}/tags/{tag}")
    other = target(HttpMethod.POST, "/drafts", NOTE_IN, NOTE)

    assert delete_for(context(CREATE, deeper, DELETE, other), CREATE) == DELETE
    assert delete_for(context(CREATE, deeper, other), CREATE) is None  # never written (RN-06)
    assert delete_for(context(other, DELETE), other) is None


def test_the_cells() -> None:
    listed = target(HttpMethod.GET, "/notes/{note_id}", response=NOTE)
    unlisted = target(HttpMethod.GET, "/raw", response={"type": "object"})
    opened = target(
        HttpMethod.GET,
        "/open",
        response={"type": "object", "properties": {"a": {}}, "additionalProperties": True},
    )
    lists = target(HttpMethod.GET, "/notes", response={"type": "array", "items": NOTE})

    cells = PropertyAccess().plan(context(CREATE, DELETE, listed, unlisted, opened, lists))

    assert [cell.target for cell in cells] == [CREATE, listed, lists]
    assert listed_properties(DOCUMENT, lists) == frozenset({"id", "text", "owner", "score"})


def test_undeclared_fields_are_top_level_keys_the_schema_does_not_list() -> None:
    declared = frozenset({"id", "text"})

    assert undeclared_fields(b'{"id": 1, "text": "a", "hash": "x"}', declared) == ["hash"]
    assert undeclared_fields(b'[{"id": 1}, {"id": 2, "role": "admin"}]', declared) == ["role"]
    assert undeclared_fields(b"not json", declared) == []


def test_the_body_it_sends() -> None:
    protected = protected_fields(DOCUMENT, CREATE, DELETE)

    assert sample_body(DOCUMENT, NOTE_IN) == {"text": "hindama", "kind": "memo"}
    assert protected["owner"] == "hindama-asignado"
    assert protected["score"] == 999999  # integer by its schema
    assert protected["secret"] is True  # readOnly in the request
    assert protected["role"] == "admin"
    assert protected["is_admin"] is True
    assert protected["permissions"] == ["admin"]
    assert "id" not in protected and "note_id" not in protected


def test_accepted_means_the_same_value_came_back() -> None:
    protected = {"owner": "hindama-asignado", "is_admin": True}

    assert accepted_fields(b'{"owner": "hindama-asignado", "is_admin": false}', protected) == [
        "owner"
    ]
    assert accepted_fields(b'{"owner": "ana"}', protected) == []


def exchange(body: bytes, headers: tuple[tuple[str, str], ...] = ()) -> Exchange:
    return Exchange("POST", "https://api.x/notes", {}, 201, headers, body)


def test_where_to_delete_it() -> None:
    assert delete_location(DELETE, exchange(b'{"note_id": "n 1"}')) == "/notes/n%201"
    assert delete_location(DELETE, exchange(b'{"id": 7}')) == "/notes/7"
    location = (("Location", "https://api.x/notes/n-9"),)
    assert delete_location(DELETE, exchange(b"", location)) == "/notes/n-9"
    assert delete_location(DELETE, exchange(b'{"id": {"a": 1}}')) is None
