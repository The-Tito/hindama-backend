"""How the login body's field names are found in the imported contract (RF-30)."""

from typing import Any

import pytest

from hindama.services.identities import _resolve

DOCUMENT = {
    "components": {
        "schemas": {
            "Login": {"$ref": "#/components/schemas/Credenciales"},
            "Credenciales": {"properties": {"correo": {}, "clave": {}}},
            "a/b": {"properties": {"x": {}}},
            "Loop": {"$ref": "#/components/schemas/Loop"},
        }
    }
}


@pytest.mark.parametrize(
    ("schema", "document", "expected"),
    [
        ({"properties": {"user": {}}}, None, {"properties": {"user": {}}}),  # inline
        (
            {"$ref": "#/components/schemas/Login"},
            DOCUMENT,
            {"properties": {"correo": {}, "clave": {}}},
        ),
        ({"$ref": "#/components/schemas/a~1b"}, DOCUMENT, {"properties": {"x": {}}}),
        ({"$ref": "#/components/schemas/Falta"}, DOCUMENT, None),
        ({"$ref": "#/components/schemas/Loop"}, DOCUMENT, None),  # cut after a few hops
        ({"$ref": "otro.yaml#/Login"}, DOCUMENT, None),  # external: never fetched
        ({"$ref": "#/components/schemas/Login"}, None, None),  # document unreadable
        (None, DOCUMENT, None),
    ],
)
def test_resolve(schema: Any, document: Any, expected: Any) -> None:
    assert _resolve(document, schema) == expected
