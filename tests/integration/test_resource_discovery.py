"""Resource discovery (CU-10 step 3; RF-36; RN-01, RN-02, RN-07, RN-11), against PostgreSQL.

The listings live on a local server (`api.hindama.test`, resolved to loopback); only loopback is
allowed on top of the production policy, as in the identity tests.
"""

import asyncio
import json
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
import structlog
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from hindama.core.resource_discovery import ResourceDiscoverer
from hindama.models import Run
from hindama.services import resources as resources_service
from tests.integration.conftest import Analyst
from tests.servers import (
    HOST,
    LOOPBACK,
    LocalServer,
    ScriptedResolver,
    UnresolvedResolver,
    allow_loopback,
)

ANA = "token-de-ana-secreto-7a1c"
BETO = "token-de-beto-secreto-3f9d"
SLOW = "token-lento-secreto-0b2e"
PASSWORD = "contraseña-que-nunca-se-ve"
SEEN: list[dict[str, Any]] = []

ORDERS = {ANA: [{"id": 101}, {"id": 102}, {"id": 101}], BETO: [{"id": 102}, {"id": "203"}]}
INVOICES = {ANA: {"items": [{"id": "F-1"}, {"sin_id": 1}, {"id": True}], "total": 3}}


def _token(request: Request) -> str:
    return request.headers.get("authorization", "").removeprefix("Bearer ")


async def orders(request: Request) -> Response:
    SEEN.append({"path": request.url.path, "headers": dict(request.headers)})
    token = _token(request)
    if token == SLOW:
        await asyncio.sleep(2)
    if token not in ORDERS:
        return JSONResponse({}, status_code=401)
    return JSONResponse(ORDERS[token])


async def invoices(request: Request) -> Response:
    SEEN.append({"path": request.url.path, "headers": dict(request.headers)})
    token = _token(request)
    if token == BETO:
        return JSONResponse({}, status_code=403)  # Beto may not list invoices
    if token not in INVOICES:
        return JSONResponse({}, status_code=401)
    return JSONResponse(INVOICES[token])


async def other(request: Request) -> Response:
    SEEN.append({"path": request.url.path, "headers": dict(request.headers)})
    return PlainTextResponse("no es JSON")


async def login(request: Request) -> Response:
    body = await request.json()
    SEEN.append({"path": request.url.path, "body": body})
    if body == {"username": "ana@ejemplo.com", "password": PASSWORD}:
        return JSONResponse({"access_token": ANA})
    return JSONResponse({}, status_code=401)


SERVER_APP = Starlette(
    routes=[
        Route("/v1/orders", orders),
        Route("/v1/invoices", invoices),
        Route("/v1/me", other),
        Route("/v1/orders/{id}", other),
        Route("/v1/auth/login", login, methods=["POST"]),
    ]
)


def _get(schema: dict[str, Any]) -> dict[str, Any]:
    return {
        "get": {
            "security": [{"bearer": []}],
            "responses": {
                "200": {"description": "ok", "content": {"application/json": {"schema": schema}}}
            },
        }
    }


ORDER = {"$ref": "#/components/schemas/Order"}
CONTRACT: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "API de pedidos", "version": "1.0"},
    "components": {
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "Order": {"type": "object", "properties": {"id": {"type": "integer"}}},
            "InvoicePage": {
                "type": "object",
                "properties": {"total": {"type": "integer"}, "items": {"type": "array"}},
            },
        },
    },
    "paths": {
        "/orders": _get({"type": "array", "items": ORDER}),
        "/invoices": _get({"$ref": "#/components/schemas/InvoicePage"}),
        "/me": _get(ORDER),  # an object without an array: not a listing
        "/orders/{id}": _get({"type": "array", "items": ORDER}),  # a path parameter: never
        "/auth/login": {"post": {"responses": {"200": {"description": "ok"}}}},
    },
}
WITHOUT_LISTINGS: dict[str, Any] = {**CONTRACT, "paths": {"/me": _get(ORDER)}}


@pytest.fixture(scope="module")
def server() -> Iterator[LocalServer]:
    with LocalServer(SERVER_APP) as running:
        yield running


@pytest.fixture(autouse=True)
def nothing_seen() -> None:
    SEEN.clear()


def discoverer(**options: Any) -> ResourceDiscoverer:
    return ResourceDiscoverer(
        resolver=ScriptedResolver([LOOPBACK]), address_policy=allow_loopback, **options
    )


@pytest.fixture
def app(app: FastAPI) -> FastAPI:
    app.state.resource_discoverer = discoverer()
    return app


class Project:
    def __init__(self, analyst: Analyst, project_id: str) -> None:
        self.analyst = analyst
        self.id = project_id
        self.operations: dict[str, str] = {}

    async def request(self, method: str, suffix: str, **kwargs: Any) -> Any:
        return await self.analyst.request(method, f"/projects/{self.id}{suffix}", **kwargs)

    async def discover(self, **body: Any) -> Any:
        return await self.request("POST", "/resources/discovery", json=body or None)

    async def import_contract(self, contract: dict[str, Any]) -> None:
        files = {"file": ("openapi.json", json.dumps(contract).encode(), "application/json")}
        response = await self.request("POST", "/contracts", files=files)
        assert response.status_code == 201, response.text
        listed = await self.request("GET", "/operations")
        self.operations = {f"{o['method']} {o['path']}": o["id"] for o in listed.json()["items"]}

    async def verify(self) -> None:
        response = await self.request("POST", "/verification", json={"method": "dns"})
        assert response.status_code == 200, response.text

    async def identity(self, name: str, token: str, **fields: Any) -> str:
        body = {
            "name": name,
            "role": "user",
            "auth_type": "bearer",
            "credential": {"token": token},
            **fields,
        }
        response = await self.request("POST", "/identities", json=body)
        assert response.status_code == 201, response.text
        identity_id: str = response.json()["id"]
        return identity_id

    async def anonymous(self) -> str:
        page = await self.request("GET", "/identities")
        identity_id: str = page.json()["items"][0]["id"]
        return identity_id

    async def resources(self) -> list[tuple[str, str, str, str, bool]]:
        page = (await self.request("GET", "/resources", params={"page_size": 100})).json()
        return [
            (r["identity_id"], r["resource_type"], r["value"], r["source"], r["confirmed"])
            for r in page["items"]
        ]


async def new_project(
    analyst: Analyst,
    server: LocalServer,
    *,
    contract: dict[str, Any] | None = CONTRACT,
    verified: bool = True,
) -> Project:
    data = await analyst.create(base_url=f"http://{HOST}:{server.port}/v1")
    project = Project(analyst, data["id"])
    if contract is not None:
        await project.import_contract(contract)
    if verified:
        await project.verify()
    return project


@pytest.fixture
async def project(ana: Analyst, server: LocalServer) -> Project:
    return await new_project(ana, server)


def assert_no_secret(payload: str) -> None:
    for secret in (ANA, BETO, PASSWORD, ANA[:-4]):
        assert secret not in payload


def summary(body: dict[str, Any], identity_id: str) -> tuple[int, int, int, str | None]:
    item = next(i for i in body["identities"] if i["identity_id"] == identity_id)
    return item["found"], item["created"], item["owned_by_other"], item["failure"]


# ------------------------------------------------------------------ discovery


async def test_each_identity_discovers_its_resources(project: Project) -> None:
    ana_id = await project.identity("Ana", ANA)
    beto_id = await project.identity("Beto", BETO)
    response = await project.discover()
    assert response.status_code == 200, response.text
    body = response.json()

    # Ana first (by creation): 102 is hers, so Beto's 102 is skipped.
    assert summary(body, ana_id) == (3, 3, 0, None)
    assert summary(body, beto_id) == (2, 1, 1, None)  # invoices answered 403, orders did not
    assert [i["identity_id"] for i in body["identities"]] == [ana_id, beto_id]
    assert (body["requests_sent"], body["truncated"]) == (4, False)
    # By type, then identifier.
    assert [(r["resource_type"], r["value"]) for r in body["created"]] == [
        ("invoices", "F-1"),
        ("orders", "101"),
        ("orders", "102"),
        ("orders", "203"),
    ]
    assert {(r["source"], r["confirmed"]) for r in body["created"]} == {("discovered", False)}
    assert sorted(await project.resources()) == sorted(
        (r["identity_id"], r["resource_type"], r["value"], "discovered", False)
        for r in body["created"]
    )
    # Only GET listings without path parameters, as each identity.
    assert sorted({s["path"] for s in SEEN}) == ["/v1/invoices", "/v1/orders"]
    assert {s["headers"]["authorization"] for s in SEEN} == {f"Bearer {ANA}", f"Bearer {BETO}"}
    assert_no_secret(response.text)


async def test_a_second_discovery_changes_nothing(project: Project) -> None:
    ana_id = await project.identity("Ana", ANA)
    first = (await project.discover()).json()
    confirmed = first["created"][0]
    response = await project.request(
        "PATCH", f"/resources/{confirmed['id']}", json={"confirmed": True}
    )
    assert response.status_code == 200

    again = (await project.discover()).json()
    assert again["created"] == []
    assert summary(again, ana_id) == (3, 0, 0, None)
    stored = await project.resources()
    assert len(stored) == 3
    assert (ana_id, confirmed["resource_type"], confirmed["value"], "discovered", True) in stored


async def test_a_manual_resource_of_another_identity_is_kept(project: Project) -> None:
    ana_id = await project.identity("Ana", ANA)
    beto_id = await project.identity("Beto", BETO)
    response = await project.request(
        "POST",
        "/resources",
        json={"identity_id": beto_id, "resource_type": "orders", "value": "101"},
    )
    assert response.status_code == 201
    body = (await project.discover(identity_ids=[ana_id])).json()
    assert summary(body, ana_id) == (3, 2, 1, None)
    assert (beto_id, "orders", "101", "manual", True) in await project.resources()


async def test_a_rejected_credential_does_not_stop_the_others(project: Project) -> None:
    wrong_id = await project.identity("Caducada", "token-vencido-0000")
    ana_id = await project.identity("Ana", ANA)
    body = (await project.discover()).json()
    assert summary(body, wrong_id) == (0, 0, 0, "rejected")
    assert summary(body, ana_id) == (3, 3, 0, None)


async def test_automatic_login(project: Project) -> None:
    login = project.operations["POST /auth/login"]
    good = await project.identity(
        "Ana",
        "",
        auth_type="login",
        credential={"username": "ana@ejemplo.com", "password": PASSWORD},
        login_operation_id=login,
    )
    bad = await project.identity(
        "Beto",
        "",
        auth_type="login",
        credential={"username": "beto@ejemplo.com", "password": "otra-clave"},
        login_operation_id=login,
    )
    response = await project.discover()
    body = response.json()
    assert summary(body, good) == (3, 3, 0, None)
    assert summary(body, bad) == (0, 0, 0, "login_failed")
    assert body["requests_sent"] == 4  # two logins, and Ana's two listings
    assert_no_secret(response.text)


async def test_a_login_operation_retired_later(project: Project) -> None:
    login_id = await project.identity(
        "Ana",
        "",
        auth_type="login",
        credential={"username": "ana@ejemplo.com", "password": PASSWORD},
        login_operation_id=project.operations["POST /auth/login"],
    )
    paths = {k: v for k, v in CONTRACT["paths"].items() if k != "/auth/login"}
    await project.import_contract({**CONTRACT, "paths": paths})
    beto_id = await project.identity("Beto", BETO)
    body = (await project.discover()).json()
    assert summary(body, login_id) == (0, 0, 0, "login_failed")
    assert summary(body, beto_id) == (2, 2, 0, None)
    assert "/v1/auth/login" not in {s["path"] for s in SEEN}


@pytest.mark.parametrize(
    ("chosen", "failure"),
    [
        (ResourceDiscoverer(resolver=ScriptedResolver([LOOPBACK])), "destination_not_allowed"),
        (ResourceDiscoverer(resolver=UnresolvedResolver()), "connection_error"),
    ],
)
async def test_a_destination_the_guard_does_not_reach(
    app: FastAPI, project: Project, chosen: ResourceDiscoverer, failure: str
) -> None:
    """The production policy blocks loopback (RF-50): nothing reaches the server."""
    app.state.resource_discoverer = chosen
    ana_id = await project.identity("Ana", ANA)
    beto_id = await project.identity("Beto", BETO)
    body = (await project.discover()).json()
    assert summary(body, ana_id) == (0, 0, 0, failure)
    assert summary(body, beto_id) == (0, 0, 0, failure)
    assert body["created"] == []
    assert SEEN == []


async def test_only_the_chosen_identities_in_their_order(project: Project) -> None:
    ana_id = await project.identity("Ana", ANA)
    beto_id = await project.identity("Beto", BETO)
    body = (await project.discover(identity_ids=[beto_id, ana_id])).json()
    assert [i["identity_id"] for i in body["identities"]] == [beto_id, ana_id]
    assert summary(body, beto_id) == (2, 2, 0, None)  # now 102 is Beto's
    assert summary(body, ana_id) == (3, 2, 1, None)

    only = (await project.discover(identity_ids=[beto_id])).json()
    assert [i["identity_id"] for i in only["identities"]] == [beto_id]


async def test_without_identities_nothing_is_sent(project: Project) -> None:
    body = (await project.discover()).json()
    assert body == {"created": [], "identities": [], "requests_sent": 0, "truncated": False}
    assert SEEN == []


@pytest.mark.parametrize(
    ("body", "field", "code"),
    [
        ({"identity_ids": "anonymous"}, "identity_ids.0", "resource.anonymous_owner"),
        ({"identity_ids": "unknown"}, "identity_ids.0", "identity.not_found"),
        ({"identity_ids": "deleted"}, "identity_ids.0", "identity.not_found"),
    ],
)
async def test_identities_that_cannot_discover(
    project: Project, body: dict[str, str], field: str, code: str
) -> None:
    ana_id = await project.identity("Ana", ANA)
    deleted = await project.identity("Borrada", BETO)
    assert (await project.request("DELETE", f"/identities/{deleted}")).status_code == 204
    chosen = {
        "anonymous": await project.anonymous(),
        "unknown": str(uuid.uuid4()),
        "deleted": deleted,
    }[body["identity_ids"]]
    response = await project.discover(identity_ids=[chosen, ana_id])
    assert response.status_code == 422, response.text
    problem = response.json()
    assert problem["code"] == code
    assert problem["errors"][0]["field"] == field
    assert SEEN == []


@pytest.mark.parametrize(
    "body",
    [{"identity_ids": []}, {"identity_ids": None}, {"identity_ids": ["no-es-uuid"]}, {"x": 1}],
)
async def test_malformed_bodies(project: Project, body: dict[str, Any]) -> None:
    response = await project.request("POST", "/resources/discovery", json=body)
    assert response.status_code == 422, response.text


async def test_repeated_identities(project: Project) -> None:
    ana_id = await project.identity("Ana", ANA)
    response = await project.discover(identity_ids=[ana_id, ana_id])
    assert response.status_code == 422
    assert SEEN == []


# ------------------------------------------------------------------ preconditions


async def test_an_unverified_project_sends_nothing(ana: Analyst, server: LocalServer) -> None:
    """RN-01: no request reaches an API whose ownership is not verified."""
    project = await new_project(ana, server, verified=False)
    await project.identity("Ana", ANA)
    response = await project.discover()
    assert (response.status_code, response.json()["code"]) == (409, "project.not_verified")
    assert SEEN == []


async def test_not_while_a_run_is_active(project: Project, owner: AsyncEngine) -> None:
    """RN-07."""
    await project.identity("Ana", ANA)
    async with AsyncSession(owner) as db, db.begin():
        db.add(
            Run(project_id=uuid.UUID(project.id), number=1, config={"modules": ["configuration"]})
        )
    response = await project.discover()
    assert (response.status_code, response.json()["code"]) == (409, "project.active_run")
    assert SEEN == []


@pytest.mark.parametrize("contract", [WITHOUT_LISTINGS, None])
async def test_without_listings_there_is_nothing_to_discover(
    ana: Analyst, server: LocalServer, contract: dict[str, Any] | None
) -> None:
    project = await new_project(ana, server, contract=contract)
    await project.identity("Ana", ANA)
    response = await project.discover()
    assert (response.status_code, response.json()["code"]) == (
        422,
        "resource.no_list_operations",
    )
    assert SEEN == []


async def test_another_analysts_project_does_not_exist(project: Project, new_analyst: Any) -> None:
    await project.identity("Ana", ANA)
    intruder: Analyst = new_analyst()
    await intruder.accept_terms()
    response = await intruder.request("POST", f"/projects/{project.id}/resources/discovery")
    assert (response.status_code, response.json()["code"]) == (404, "resource.not_found")
    assert SEEN == []


# ------------------------------------------------------------------ caps


async def test_the_request_cap_keeps_what_was_found(app: FastAPI, project: Project) -> None:
    app.state.resource_discoverer = discoverer(max_requests=3)
    ana_id = await project.identity("Ana", ANA)
    beto_id = await project.identity("Beto", BETO)
    carla_id = await project.identity("Carla", BETO + "-c")
    body = (await project.discover()).json()
    assert (body["requests_sent"], body["truncated"]) == (3, True)
    assert summary(body, ana_id) == (3, 3, 0, None)
    # Beto's first listing (invoices) answered 403: the cap came before an answer.
    assert summary(body, beto_id) == (0, 0, 0, "not_attempted")
    assert summary(body, carla_id) == (0, 0, 0, "not_attempted")
    assert len(await project.resources()) == 3


async def test_the_time_cap_keeps_what_was_found(app: FastAPI, project: Project) -> None:
    app.state.resource_discoverer = discoverer(timeout=1.0)
    ana_id = await project.identity("Ana", ANA)
    slow_id = await project.identity("Lenta", SLOW)
    beto_id = await project.identity("Beto", BETO)
    body = (await project.discover()).json()
    assert body["truncated"] is True
    assert summary(body, ana_id) == (3, 3, 0, None)
    assert summary(body, slow_id)[3] == "not_attempted"
    assert summary(body, beto_id) == (0, 0, 0, "not_attempted")
    assert len(await project.resources()) == 3


# ------------------------------------------------------------------ never in the logs (RN-11)


async def test_the_credential_never_reaches_the_logs(
    project: Project, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(resources_service, "log", structlog.get_logger("test"))
    await project.identity("Ana", ANA)
    with structlog.testing.capture_logs() as logs:
        response = await project.discover()
    assert response.status_code == 200
    events = [entry for entry in logs if entry["event"] == "resources_discovered"]
    assert events and events[0]["created"] == 3
    assert_no_secret(repr(logs))
