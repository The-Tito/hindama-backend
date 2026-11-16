"""Reading an OpenAPI 3 contract (CU-08; RF-22 to RF-25, RF-27): untrusted input, no network."""

import json
from typing import Any

import pytest
import yaml

from hindama.core import openapi_import
from hindama.core.openapi_import import (
    ContractError,
    ParsedContract,
    normalize_path,
    parse_contract,
    read_document,
)

HOST = "api.ejemplo.com"


def document(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {"title": "API de pedidos", "version": "1.0"},
        "paths": {
            "/orders/{orderId}": {
                "get": {"responses": {"200": {"description": "ok"}}},
            }
        },
    }
    base.update(overrides)
    return base


def parse(doc: dict[str, Any] | str | bytes) -> ParsedContract:
    if isinstance(doc, dict):
        doc = json.dumps(doc)
    if isinstance(doc, str):
        doc = doc.encode()
    return parse_contract(doc, HOST)


def rejected(doc: dict[str, Any] | str | bytes) -> ContractError:
    with pytest.raises(ContractError) as error:
        parse(doc)
    return error.value


def fields(error: ContractError) -> list[tuple[str | None, str]]:
    return [(issue.field, issue.code) for issue in error.issues]


def warnings(contract: ParsedContract) -> list[tuple[str, str | None]]:
    return [(w.code, w.location) for w in contract.warnings]


# ---------------------------------------------------------------- reading


def test_json_and_yaml_are_both_read() -> None:
    doc = document()
    from_json = parse(json.dumps(doc))
    from_yaml = parse(yaml.safe_dump(doc))
    assert (from_json.format, from_yaml.format) == ("json", "yaml")
    assert from_json.operations == from_yaml.operations
    assert from_json.openapi_version == "3.0.3"
    assert from_json.api_title == "API de pedidos"


def test_a_utf8_bom_is_accepted() -> None:
    assert parse(b"\xef\xbb\xbf" + json.dumps(document()).encode()).format == "json"


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"\xff\xfe{}", "contract.encoding"),
        (b"   \n", "contract.empty"),
        (b'{"openapi": "3.0.3",', "contract.invalid_json"),
        (b'{"x": NaN}', "contract.invalid_json"),
        (b"openapi: [3.0\n  info: x", "contract.invalid_yaml"),
        (b"a: 1\n---\nb: 2\n", "contract.invalid_yaml"),
    ],
)
def test_unreadable_documents(raw: bytes, code: str) -> None:
    error = rejected(raw)
    assert error.code == "contract.invalid"
    assert error.issues[0].code == code


def test_json_errors_point_to_the_line() -> None:
    error = rejected(b'{\n  "openapi": "3.0.3",\n  "info": }\n')
    assert error.issues[0].field == "línea 3"


def test_yaml_errors_point_to_the_line() -> None:
    error = rejected("openapi: 3.0.3\ninfo:\n  title: x\n   version: 1\n")
    assert error.issues[0].field == "línea 4"


def test_yaml_anchors_and_aliases_are_rejected() -> None:
    # "Billion laughs": nine levels of ten aliases are 10^9 nodes once traversed.
    lol = ["a: &a [x, x, x, x, x, x, x, x, x, x]"]
    for level in range(1, 9):
        refs = ", ".join([f"*{chr(96 + level)}"] * 10)
        lol.append(f"{chr(97 + level)}: &{chr(97 + level)} [{refs}]")
    error = rejected("\n".join(lol))
    assert fields(error) == [("línea 1", "contract.yaml_alias")]


def test_nesting_is_bounded() -> None:
    deep = "[" * 200 + "]" * 200
    assert rejected(deep).issues[0].code == "contract.too_deep"
    very_deep = "[" * 100_000 + "]" * 100_000  # the parser's own recursion
    assert rejected(very_deep).issues[0].code == "contract.too_deep"


def test_values_become_storable_json() -> None:
    _, value = read_document(b'200: ok\ntrue: 1\nwhen: 2026-11-15\nnan: .nan\nnul: "a\\0b"\n')
    assert value == {"200": "ok", "true": 1, "when": "2026-11-15", "nan": "nan", "nul": "ab"}


def test_nul_characters_never_reach_the_database() -> None:
    doc = document(info={"title": "API\u0000 de pedidos", "version": "1"})
    assert parse(doc).api_title == "API de pedidos"


# ---------------------------------------------------------------- versions (RF-25)


def test_swagger_2_is_not_supported() -> None:
    error = rejected({"swagger": "2.0", "info": {}, "paths": {}})
    assert error.code == "contract.unsupported_version"
    assert fields(error) == [("/swagger", "contract.unsupported_version")]


@pytest.mark.parametrize("version", ["3.2.0", "4.0.0", "3.0", "2.0"])
def test_other_versions_are_not_supported(version: str) -> None:
    assert rejected(document(openapi=version)).code == "contract.unsupported_version"


def test_openapi_31_is_supported() -> None:
    contract = parse(document(openapi="3.1.0"))
    assert contract.openapi_version == "3.1.0"


def test_a_document_that_is_not_an_object() -> None:
    assert fields(rejected("[1, 2]")) == [("/", "contract.invalid_type")]


def test_missing_openapi_field() -> None:
    doc = document()
    del doc["openapi"]
    assert fields(rejected(doc)) == [("/openapi", "contract.required_field")]


def test_errors_are_collected_with_their_location() -> None:
    doc = document(info={}, paths={"/a": {"get": {}}, "b": {}})
    assert fields(rejected(doc)) == [
        ("/info/title", "contract.required_field"),
        ("/info/version", "contract.required_field"),
        ("/paths/~1a/get/responses", "contract.required_field"),
        ("/paths/b", "contract.invalid_value"),
    ]


def test_responses_and_paths_are_optional_in_31() -> None:
    contract = parse({"openapi": "3.1.0", "info": {"title": "t", "version": "1"}})
    assert contract.operations == []
    doc = document(openapi="3.1.0", paths={"/a": {"get": {}}})
    assert parse(doc).operations[0].schemas["responses"] == {}


def test_the_number_of_errors_is_bounded() -> None:
    doc = document(paths={f"/p{i}": {"get": {}} for i in range(50)})
    assert len(rejected(doc).issues) == openapi_import.MAX_ERRORS


def test_the_number_of_operations_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(openapi_import, "MAX_OPERATIONS", 3)
    ok = {"responses": {"200": {"description": "ok"}}}
    doc = document(paths={f"/p{i}": {"get": ok} for i in range(4)})
    assert fields(rejected(doc)) == [("/paths", "contract.too_many_operations")]


# ---------------------------------------------------------------- operations (RF-24)


def test_paths_are_normalized_by_parameter_name() -> None:
    assert normalize_path("/users/{userId}/orders/{id}") == "/users/{}/orders/{}"


def test_two_paths_that_only_differ_in_a_parameter_name_are_one_operation() -> None:
    ok = {"responses": {"200": {"description": "ok"}}}
    doc = document(paths={"/users/{id}": {"get": ok}, "/users/{userId}": {"get": ok}})
    assert fields(rejected(doc)) == [
        ("/paths/~1users~1{userId}/get", "contract.duplicate_operation")
    ]


def test_an_operation_is_extracted() -> None:
    doc = document(
        components={
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "Bearer"},
                "key": {"type": "apiKey", "in": "header", "name": "X-Key"},
            },
            "schemas": {"Order": {"type": "object"}},
        },
        security=[{"bearer": []}],
        paths={
            "/orders/{orderId}": {
                "parameters": [
                    {"name": "orderId", "in": "path", "schema": {"type": "integer"}},
                    {"name": "expand", "in": "query", "schema": {"type": "string"}},
                ],
                "patch": {
                    "operationId": "updateOrder",
                    "summary": "Editar un pedido",
                    "tags": ["pedidos", 7],
                    "parameters": [
                        {"name": "expand", "in": "query", "required": True},
                        {"name": "X-Trace", "in": "header", "schema": {"type": ["string", "null"]}},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Order"}},
                            "application/merge-patch+json": {"schema": {"type": "object"}},
                        },
                    },
                    "security": [{"key": []}, {}],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    )
    [op] = parse(doc).operations
    assert (op.method, op.path, op.normalized_path) == ("PATCH", "/orders/{orderId}", "/orders/{}")
    assert (op.operation_id, op.summary, op.tags) == (
        "updateOrder",
        "Editar un pedido",
        ["pedidos"],
    )
    assert [(p["name"], p["location"], p["required"], p["type"]) for p in op.parameters] == [
        ("orderId", "path", True, "integer"),  # path parameters are always required
        ("expand", "query", True, None),  # the operation's own wins over the path item's
        ("X-Trace", "header", False, "string"),
    ]
    assert op.request_body == {
        "required": True,
        "content_types": ["application/json", "application/merge-patch+json"],
    }
    assert op.security == [{"scheme": "key", "type": "api_key"}]  # replaces the document's
    assert op.schemas["refs"] == ["#/components/schemas/Order"]


def test_security_types_and_public_operations() -> None:
    schemes = {
        "b": {"type": "http", "scheme": "bearer"},
        "basic": {"type": "http", "scheme": "basic"},
        "digest": {"type": "http", "scheme": "digest"},
        "o": {"type": "oauth2", "flows": {}},
        "oidc": {"type": "openIdConnect", "openIdConnectUrl": "https://x"},
        "mtls": {"type": "mutualTLS"},
    }
    ok = {"responses": {"200": {"description": "ok"}}}
    doc = document(
        components={"securitySchemes": schemes},
        security=[{name: []} for name in schemes],
        paths={"/private": {"get": ok}, "/public": {"get": {**ok, "security": []}}},
    )
    private, public = parse(doc).operations
    assert [s["type"] for s in private.security] == [
        "http_bearer",
        "http_basic",
        "other",
        "oauth2",
        "openid_connect",
        "other",
    ]
    assert public.security == []


def test_an_undeclared_security_scheme_is_a_warning() -> None:
    ok = {"responses": {"200": {"description": "ok"}}, "security": [{"ghost": []}]}
    contract = parse(document(paths={"/a": {"get": ok}}))
    assert contract.operations[0].security == [{"scheme": "ghost", "type": "other"}]
    assert warnings(contract) == [("contract.unparsed_element", "/paths/~1a/get/security")]


def test_invalid_parameters() -> None:
    doc = document(
        paths={
            "/a": {
                "parameters": "nope",
                "get": {
                    "parameters": [{"in": "query"}, {"name": "x", "in": "body"}, 3],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        }
    )
    assert fields(rejected(doc)) == [
        ("/paths/~1a/parameters", "contract.invalid_type"),
        ("/paths/~1a/get/parameters/0/name", "contract.required_field"),
        ("/paths/~1a/get/parameters/1/in", "contract.invalid_value"),
        ("/paths/~1a/get/parameters/2", "contract.invalid_type"),
    ]


def test_a_parameter_with_content_instead_of_schema() -> None:
    parameter = {
        "name": "filter",
        "in": "query",
        "content": {"application/json": {"schema": {"type": "object"}}},
    }
    ok = {"parameters": [parameter], "responses": {"200": {"description": "ok"}}}
    [op] = parse(document(paths={"/a": {"get": ok}})).operations
    assert op.parameters[0]["type"] == "object"


def test_invalid_operation_parts() -> None:
    doc = document(
        paths={
            "/a": {"get": "nope"},
            "/b": "nope",
            "/c": {
                "post": {
                    "requestBody": {"description": "sin content"},
                    "responses": {"200": "nope", "x-extra": 1},
                }
            },
            "/d": {"get": {"responses": []}},
        }
    )
    assert fields(rejected(doc)) == [
        ("/paths/~1a/get", "contract.invalid_type"),
        ("/paths/~1b", "contract.invalid_type"),
        ("/paths/~1c/post/requestBody", "contract.required_field"),
        ("/paths/~1c/post/responses/200", "contract.invalid_type"),
        ("/paths/~1d/get/responses", "contract.invalid_type"),
    ]
    assert fields(rejected(document(paths=[]))) == [("/paths", "contract.invalid_type")]


def test_extensions_are_ignored() -> None:
    ok = {"responses": {"200": {"description": "ok"}}}
    contract = parse(document(paths={"x-internal": {"a": 1}, "/a": {"get": ok, "x-y": 1}}))
    assert [op.path for op in contract.operations] == ["/a"]


# ---------------------------------------------------------------- references (RF-23)


def components(**parts: Any) -> dict[str, Any]:
    return {"components": parts}


def test_internal_references_are_resolved() -> None:
    doc = document(
        **components(
            parameters={
                "Id": {"name": "id", "in": "path", "schema": {"$ref": "#/components/schemas/Id"}}
            },
            requestBodies={
                "Order": {"content": {"application/json": {"schema": {"type": "object"}}}}
            },
            responses={
                "Ok": {
                    "description": "ok",
                    "content": {"text/plain": {"schema": {"type": "string"}}},
                }
            },
            schemas={"Id": {"type": "integer"}},
        ),
        paths={
            "/orders/{id}": {"$ref": "#/x-shared"},
        },
    )
    doc["x-shared"] = {
        "put": {
            "parameters": [{"$ref": "#/components/parameters/Id"}],
            "requestBody": {"$ref": "#/components/requestBodies/Order"},
            "responses": {"200": {"$ref": "#/components/responses/Ok"}},
        }
    }
    [op] = parse(doc).operations
    assert op.parameters[0]["type"] == "integer"
    # A component is stored as a reference to it, never copied into each operation.
    assert op.parameters[0]["schema"] == {"$ref": "#/components/parameters/Id/schema"}
    assert op.schemas["request"] == {
        "application/json": {
            "$ref": "#/components/requestBodies/Order/content/application~1json/schema"
        }
    }
    assert op.schemas["responses"] == {
        "200": {"text/plain": {"$ref": "#/components/responses/Ok/content/text~1plain/schema"}}
    }
    assert op.schemas["refs"] == [
        "#/components/parameters/Id/schema",
        "#/components/requestBodies/Order/content/application~1json/schema",
        "#/components/responses/Ok/content/text~1plain/schema",
        "#/components/schemas/Id",
    ]


def test_external_references_are_not_followed() -> None:
    ok = {"description": "ok"}
    doc = document(
        paths={
            "/a": {"$ref": "other.yaml#/paths/~1a"},
            "/b": {
                "get": {
                    "parameters": [{"$ref": "https://evil.example/p.json"}],
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {"application/json": {"schema": {"$ref": "s.json#/S"}}},
                        },
                        "404": ok,
                    },
                }
            },
        }
    )
    contract = parse(doc)
    assert [op.path for op in contract.operations] == ["/b"]
    assert contract.operations[0].parameters == []
    assert warnings(contract) == [
        ("contract.external_reference", "/paths/~1a/$ref"),
        ("contract.external_reference", "/paths/~1b/get/parameters/0/$ref"),
        (
            "contract.external_reference",
            "/paths/~1b/get/responses/200/content/application~1json/schema/$ref",
        ),
    ]


def test_broken_and_circular_references() -> None:
    doc = document(
        **components(
            parameters={
                "A": {"$ref": "#/components/parameters/B"},
                "B": {"$ref": "#/components/parameters/A"},
            }
        ),
        paths={
            "/a": {
                "get": {
                    "parameters": [
                        {"$ref": "#/components/parameters/Missing"},
                        {"$ref": "#/components/parameters/A"},
                        {"$ref": 7},
                    ],
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {"a/b": {"schema": {"$ref": "#/components/schemas/Nope"}}},
                        }
                    },
                }
            }
        },
    )
    assert fields(rejected(doc)) == [
        ("/paths/~1a/get/parameters/0/$ref", "contract.unresolved_reference"),
        ("/components/parameters/B", "contract.circular_reference"),
        ("/paths/~1a/get/parameters/2/$ref", "contract.invalid_type"),
        ("/paths/~1a/get/responses/200/content/a~1b/schema/$ref", "contract.unresolved_reference"),
    ]


def test_recursive_schemas_are_fine() -> None:
    node = {
        "type": "object",
        "properties": {
            "children": {"type": "array", "items": {"$ref": "#/components/schemas/Node"}}
        },
    }
    response = {
        "description": "ok",
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}},
    }
    doc = document(
        **components(schemas={"Node": node}),
        paths={"/tree": {"get": {"responses": {"200": response}}}},
    )
    [op] = parse(doc).operations
    assert op.schemas["refs"] == ["#/components/schemas/Node"]


def test_a_change_in_a_shared_schema_changes_the_fingerprint() -> None:
    response = {
        "description": "ok",
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Order"}}},
    }
    paths = {"/orders": {"get": {"responses": {"200": response}}}}
    before = parse(document(**components(schemas={"Order": {"type": "object"}}), paths=paths))
    after = parse(document(**components(schemas={"Order": {"type": "array"}}), paths=paths))
    assert before.operations[0].schemas["refs"] == after.operations[0].schemas["refs"]
    assert before.operations[0].schemas["refs_sha256"] != after.operations[0].schemas["refs_sha256"]


def test_json_pointer_escapes_in_references() -> None:
    doc = document(**components(schemas={"a/b~c d": {"type": "string"}}))
    doc["paths"]["/x"] = {
        "get": {
            "responses": {
                "200": {
                    "description": "ok",
                    "content": {"t/p": {"schema": {"$ref": "#/components/schemas/a~1b~0c%20d"}}},
                }
            }
        }
    }
    assert parse(doc).operations[1].schemas["refs"] == ["#/components/schemas/a~1b~0c%20d"]


# ---------------------------------------------------------------- warnings (RF-27)


def test_servers_on_another_host() -> None:
    ok = {"responses": {"200": {"description": "ok"}}}
    doc = document(
        servers=[
            {"url": "https://API.ejemplo.com/v1"},
            {"url": "/v1"},
            {"url": "https://staging.ejemplo.com"},
            {"url": "https://{env}.ejemplo.com", "variables": {"env": {"default": "api"}}},
            {"url": "https://{region}.ejemplo.com"},
            {"url": "http://[::1"},
            "nope",
        ],
        paths={
            "/a": {
                "servers": [{"url": "https://otro.com"}],
                "get": {**ok, "servers": [{"url": "https://tercero.com"}]},
            }
        },
    )
    assert warnings(parse(doc)) == [
        ("contract.servers_mismatch", "/servers/2/url"),
        ("contract.servers_mismatch", "/paths/~1a/servers/0/url"),
        ("contract.servers_mismatch", "/paths/~1a/get/servers/0/url"),
    ]


def test_webhooks_and_callbacks_are_reported() -> None:
    ok = {"responses": {"200": {"description": "ok"}}, "callbacks": {"x": {}}}
    doc = document(openapi="3.1.0", webhooks={"newOrder": {}}, paths={"/a": {"post": ok}})
    assert warnings(parse(doc)) == [
        ("contract.unparsed_element", "/paths/~1a/post/callbacks"),
        ("contract.unparsed_element", "/webhooks"),
    ]


def test_warnings_are_deduplicated_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(openapi_import, "MAX_WARNINGS", 2)
    doc = document(servers=[{"url": f"https://s{i}.com"} for i in range(5)])
    assert len(parse(doc).warnings) == 2
