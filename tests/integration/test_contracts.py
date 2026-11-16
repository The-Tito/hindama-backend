"""`/contracts` and `/operations` (CU-08; RF-22 to RF-27; RN-01, RN-02), against PostgreSQL.

Import by URL goes through the SSRF guard to a local server (`docs.hindama.test`, resolved to
loopback); only loopback is allowed on top of the production policy.
"""

import json
from collections.abc import Iterator
from typing import Any

import pytest
import yaml
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from hindama.models.base import MAX_CONTRACT_BYTES
from tests.dns import FakeResolver
from tests.integration.conftest import Analyst
from tests.servers import LOOPBACK, LocalServer, allow_loopback

DOCS_HOST = "docs.hindama.test"
OK = {"responses": {"200": {"description": "ok"}}}

# What the local server answers on /openapi.yaml, and how many times it was asked.
SERVED: dict[str, Any] = {}


async def served(_: Request) -> Response:
    SERVED["hits"] += 1
    return Response(SERVED["body"], status_code=SERVED["status"])


SERVER_APP = Starlette(routes=[Route("/openapi.yaml", served)])


@pytest.fixture(scope="module")
def server() -> Iterator[LocalServer]:
    with LocalServer(SERVER_APP) as running:
        yield running


@pytest.fixture(autouse=True)
def nothing_served() -> None:
    SERVED.clear()
    SERVED.update(status=404, body=b"", hits=0)


@pytest.fixture
def app(app: FastAPI, resolver: FakeResolver) -> FastAPI:
    resolver.set(DOCS_HOST, LOOPBACK)
    app.state.address_policy = allow_loopback
    return app


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def to_yaml(doc: dict[str, Any]) -> bytes:
    """Hindama rejects YAML anchors; PyYAML writes them for objects repeated in a dict."""
    return yaml.dump(doc, Dumper=_NoAliases).encode()


def document(paths: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "API de pedidos", "version": "1.0"},
        "paths": paths if paths is not None else {"/orders": {"get": OK, "post": OK}},
        **extra,
    }


def as_file(doc: dict[str, Any] | bytes, name: str = "openapi.json") -> dict[str, Any]:
    content = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    return {"files": {"file": (name, content, "application/json")}}


async def import_file(
    analyst: Analyst, project: dict[str, Any], doc: dict[str, Any] | bytes, **kwargs: Any
) -> Any:
    return await analyst.request(
        "POST", f"/projects/{project['id']}/contracts", **as_file(doc, **kwargs)
    )


async def import_url(analyst: Analyst, project: dict[str, Any], url: str) -> Any:
    return await analyst.request(
        "POST", f"/projects/{project['id']}/contracts", files={"url": (None, url)}
    )


async def operations(analyst: Analyst, project: dict[str, Any], query: str = "") -> Any:
    response = await analyst.request("GET", f"/projects/{project['id']}/operations{query}")
    assert response.status_code == 200, response.text
    return response.json()


# ------------------------------------------------------------------ import (CU-08)


async def test_import_a_file(ana: Analyst) -> None:
    project = await ana.create()
    doc = document(
        servers=[{"url": "https://staging.ejemplo.com"}],
        paths={
            "/orders/{orderId}": {
                "get": {
                    "operationId": "getOrder",
                    "summary": "Un pedido",
                    "tags": ["pedidos"],
                    "parameters": [{"name": "orderId", "in": "path", "schema": {"type": "string"}}],
                    "security": [{"bearer": []}],
                    **OK,
                },
                "delete": OK,
            }
        },
        components={"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    )

    response = await import_file(ana, project, doc, name="mi contrato.json")

    assert response.status_code == 201, response.text
    body = response.json()
    assert response.headers["location"] == f"/projects/{project['id']}/contracts/{body['id']}"
    assert body | {"id": None, "imported_at": None, "sha256": None} == {
        "id": None,
        "number": 1,
        "source": "file",
        "openapi_version": "3.0.3",
        "operation_count": 2,
        "imported_at": None,
        "source_url": None,
        "file_name": "mi contrato.json",
        "format": "json",
        "api_title": "API de pedidos",
        "sha256": None,
        "is_current": True,
        "warnings": [
            {
                "code": "contract.servers_mismatch",
                "message": "Los servidores del contrato no coinciden con la URL base; se usará "
                "la URL base del proyecto.",
                "location": "/servers/0/url",
            }
        ],
        "changes": None,
    }
    page = await operations(ana, project)
    assert page["total"] == 2
    delete, get = page["items"]  # ordered by path, then method
    assert (delete["method"], get["method"]) == ("DELETE", "GET")
    assert get | {"id": None} == {
        "id": None,
        "method": "GET",
        "path": "/orders/{orderId}",
        "operation_id": "getOrder",
        "summary": "Un pedido",
        "tags": ["pedidos"],
        "parameters": [{"name": "orderId", "location": "path", "required": True, "type": "string"}],
        "body": None,
        "security": [{"scheme": "bearer", "type": "http_bearer"}],
        "retired_at": None,
        "suggested_policy": None,  # proposed from task 2.6 on (RF-40)
        "policy": None,
        "owner_field": None,
        "confirmed_at": None,
        "modified_at": None,
        "resource_parameters": [],
        "is_login_candidate": False,
    }
    dashboard = (await ana.request("GET", f"/projects/{project['id']}")).json()
    assert dashboard["current_contract"]["id"] == body["id"]
    assert "no_contract" not in dashboard["modules"][0]["missing"]


async def test_import_yaml(ana: Analyst) -> None:
    project = await ana.create()
    raw = to_yaml(document())
    response = await import_file(ana, project, raw, name="openapi.yaml")
    assert response.status_code == 201
    assert response.json()["format"] == "yaml"


async def test_the_same_document_does_not_create_a_version(ana: Analyst) -> None:
    project = await ana.create()
    first = (await import_file(ana, project, document())).json()

    again = await import_file(ana, project, document())

    assert again.status_code == 200
    assert again.json()["id"] == first["id"]
    assert again.json()["warnings"][-1]["code"] == "contract.unchanged"
    listed = (await ana.request("GET", f"/projects/{project['id']}/contracts")).json()
    assert listed["total"] == 1


async def test_versions_and_their_differences(ana: Analyst) -> None:
    project = await ana.create()
    v1 = (
        await import_file(
            ana, project, document({"/a": {"get": OK}, "/b": {"get": OK}, "/c/{id}": {"get": OK}})
        )
    ).json()
    changed = {
        "responses": {"200": {"description": "ok"}},
        "parameters": [{"name": "q", "in": "query"}],
    }

    response = await import_file(
        ana,
        project,
        document({"/a": {"get": OK}, "/c/{cid}": {"get": changed}, "/d": {"post": OK}}),
    )

    assert response.status_code == 201
    v2 = response.json()
    assert v2["number"] == 2
    ops = {
        f"{op['method']} {op['path']}": op["id"]
        for op in (await operations(ana, project, "?include_retired=true"))["items"]
    }

    def ref(key: str) -> dict[str, str]:
        method, path = key.split(" ")
        return {"id": ops[key], "method": method, "path": path}

    assert v2["changes"] == {
        "previous_version": 1,
        "added": [ref("POST /d")],
        "modified": [ref("GET /c/{cid}")],  # same operation, renamed parameter and a new one
        "removed": [ref("GET /b")],
    }
    current = await operations(ana, project)
    assert [op["path"] for op in current["items"]] == ["/a", "/c/{cid}", "/d"]
    retired = (await operations(ana, project, "?include_retired=true"))["items"]
    assert [op["retired_at"] is not None for op in retired] == [False, True, False, False]
    first = (await ana.request("GET", f"/projects/{project['id']}/contracts/{v1['id']}")).json()
    assert first["is_current"] is False
    assert first["changes"] is None

    # /b comes back: the same operation, no longer retired.
    v3 = (await import_file(ana, project, document({"/a": {"get": OK}, "/b": {"get": OK}}))).json()
    assert v3["changes"]["added"] == [ref("GET /b")]
    assert [op["path"] for op in (await operations(ana, project))["items"]] == ["/a", "/b"]
    listed = (await ana.request("GET", f"/projects/{project['id']}/contracts?page_size=2")).json()
    assert [v["number"] for v in listed["items"]] == [3, 2]
    assert listed["total"] == 3


async def test_login_candidates_are_marked(ana: Analyst) -> None:
    project = await ana.create()
    await import_file(
        ana, project, document({"/auth/login": {"post": OK}, "/orders": {"post": OK}})
    )
    items = (await operations(ana, project))["items"]
    assert [(op["path"], op["is_login_candidate"]) for op in items] == [
        ("/auth/login", True),
        ("/orders", False),
    ]


async def test_operations_filter_and_pages(ana: Analyst) -> None:
    project = await ana.create()
    assert (await operations(ana, project))["items"] == []  # no contract yet
    paths = {f"/r{i}": {"get": OK, "post": OK} for i in range(3)}
    await import_file(ana, project, document(paths))

    posts = await operations(ana, project, "?method=POST")
    assert [op["path"] for op in posts["items"]] == ["/r0", "/r1", "/r2"]
    page = await operations(ana, project, "?page=2&page_size=4")
    assert page["total"] == 6
    assert [(op["method"], op["path"]) for op in page["items"]] == [("GET", "/r2"), ("POST", "/r2")]


# ------------------------------------------------------------------ errors (RF-25, E1 to E4)


async def test_an_invalid_document_says_where(ana: Analyst) -> None:
    project = await ana.create()
    response = await import_file(ana, project, document({"/orders": {"get": {}}}))
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "contract.invalid"
    assert body["errors"] == [
        {
            "field": "/paths/~1orders/get/responses",
            "code": "contract.required_field",
            "message": "La operación no declara respuestas.",
        }
    ]


async def test_swagger_2(ana: Analyst) -> None:
    project = await ana.create()
    response = await import_file(ana, project, {"swagger": "2.0", "info": {}, "paths": {}})
    assert response.json()["code"] == "contract.unsupported_version"


async def test_exactly_one_source(ana: Analyst, server: LocalServer) -> None:
    project = await ana.create()
    path = f"/projects/{project['id']}/contracts"
    neither = await ana.request("POST", path, files={"other": (None, "x")})
    both = await ana.request(
        "POST",
        path,
        files={
            "file": ("a.json", json.dumps(document()).encode(), "application/json"),
            "url": (None, f"http://{DOCS_HOST}:{server.port}/openapi.yaml"),
        },
    )
    assert neither.json()["code"] == both.json()["code"] == "contract.source_required"
    assert SERVED["hits"] == 0


async def test_a_file_over_5_mb(ana: Analyst) -> None:
    project = await ana.create()
    response = await import_file(ana, project, b" " * (MAX_CONTRACT_BYTES + 1))
    assert response.status_code == 413
    assert response.json()["code"] == "contract.too_large"


# ------------------------------------------------------------------ by URL (RN-01 exception)


async def test_import_by_url(ana: Analyst, server: LocalServer) -> None:
    project = await ana.create()  # not verified: importing the contract does not need it
    url = f"http://{DOCS_HOST}:{server.port}/openapi.yaml"
    SERVED.update(status=200, body=to_yaml(document()))

    response = await import_url(ana, project, url)

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["source"], body["source_url"], body["file_name"]) == ("url", url, None)
    assert SERVED["hits"] == 1


@pytest.mark.parametrize(
    ("status", "body", "code", "http_status"),
    [
        (404, b"", "contract.url_unreachable", 422),
        (200, b" " * (MAX_CONTRACT_BYTES + 1), "contract.too_large", 413),
    ],
)
async def test_url_failures(
    ana: Analyst, server: LocalServer, status: int, body: bytes, code: str, http_status: int
) -> None:
    project = await ana.create()
    SERVED.update(status=status, body=body)
    response = await import_url(ana, project, f"http://{DOCS_HOST}:{server.port}/openapi.yaml")
    assert response.status_code == http_status
    assert response.json()["code"] == code


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://docs.hindama.test/openapi.yaml", "contract.url_not_allowed"),
        ("http://user:pw@docs.hindama.test/openapi.yaml", "contract.url_not_allowed"),
        ("http://[::1/openapi.yaml", "contract.url_not_allowed"),
        ("http://10.0.0.8/openapi.yaml", "contract.url_not_allowed"),
        ("http://169.254.169.254/latest/meta-data/", "contract.url_not_allowed"),
        ("http://docs.hindama.test:99999/x", "contract.url_not_allowed"),
        ("http://desconocido.hindama.test/x", "contract.url_unreachable"),
    ],
)
async def test_urls_that_are_never_fetched(
    ana: Analyst, resolver: FakeResolver, url: str, code: str
) -> None:
    resolver.unresolved.add("desconocido.hindama.test")
    project = await ana.create()
    response = await import_url(ana, project, url)
    assert response.status_code == 422
    assert response.json()["code"] == code
    assert response.json()["errors"][0]["field"] == "url"


# ------------------------------------------------------------------ isolation (RN-02)


async def test_another_analysts_project(
    ana: Analyst, new_analyst: Any, server: LocalServer
) -> None:
    project = await ana.create()
    version = (await import_file(ana, project, document())).json()
    SERVED.update(status=200, body=to_yaml(document()))
    beto: Analyst = new_analyst()
    await beto.accept_terms()
    base = f"/projects/{project['id']}"

    responses = [
        await import_url(beto, project, f"http://{DOCS_HOST}:{server.port}/openapi.yaml"),
        await import_file(beto, project, document({"/x": {"get": OK}})),
        await beto.request("GET", f"{base}/contracts"),
        await beto.request("GET", f"{base}/contracts/{version['id']}"),
        await beto.request("GET", f"{base}/operations"),
    ]

    assert [r.status_code for r in responses] == [404] * 5
    assert SERVED["hits"] == 0  # nothing downloaded on behalf of someone else's project
    assert (await ana.request("GET", f"{base}/contracts")).json()["total"] == 1


async def test_a_version_of_another_project(ana: Analyst) -> None:
    first, second = await ana.create(), await ana.create()
    version = (await import_file(ana, first, document())).json()
    response = await ana.request("GET", f"/projects/{second['id']}/contracts/{version['id']}")
    assert response.status_code == 404
