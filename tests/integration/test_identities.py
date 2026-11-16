"""`/identities` (CU-09; RF-28 to RF-34; RN-01, RN-02, RN-11), against PostgreSQL.

The credential test reaches a local server (`api.hindama.test`, resolved to loopback); only loopback
is allowed on top of the production policy.
"""

import json
import uuid
from collections.abc import Iterator
from datetime import date
from typing import Any

import pytest
import structlog
from fastapi import FastAPI
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from hindama.core.credentials import Credential, CredentialCipher
from hindama.core.identity_probe import IdentityProber
from hindama.models import Finding, FindingEvent, FindingMetric, Identity, Resource, Run
from hindama.services import identities as identities_service
from tests.integration.conftest import Analyst
from tests.servers import HOST, LOOPBACK, LocalServer, ScriptedResolver, allow_loopback

TOKEN = "token-secreto-de-ana-9f2a"
PASSWORD = "contraseña-que-nunca-se-ve"
SEEN: list[dict[str, Any]] = []


async def orders(request: Request) -> Response:
    SEEN.append({"path": request.url.path, "headers": dict(request.headers)})
    ok = request.headers.get("authorization") == f"Bearer {TOKEN}"
    return JSONResponse({}, status_code=200 if ok else 401)


async def login(request: Request) -> Response:
    body = await request.json()
    SEEN.append({"path": "/auth/login", "body": body})
    if body == {"correo": "ana@ejemplo.com", "clave": PASSWORD}:
        return JSONResponse({"access_token": TOKEN})
    return JSONResponse({}, status_code=401)


SERVER_APP = Starlette(
    routes=[
        Route("/v1/orders", orders),
        Route("/v1/me", orders),
        Route("/v1/auth/login", login, methods=["POST"]),
    ]
)

SECURED = {"security": [{"bearer": []}], "responses": {"200": {"description": "ok"}}}
OPEN = {"responses": {"200": {"description": "ok"}}}
CONTRACT = {
    "openapi": "3.0.3",
    "info": {"title": "API de pedidos", "version": "1.0"},
    "components": {
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "Login": {
                "type": "object",
                "properties": {"correo": {"type": "string"}, "clave": {"type": "string"}},
            }
        },
    },
    "paths": {
        "/public": {"get": OPEN},
        "/me": {"get": SECURED},
        "/orders": {"get": SECURED, "post": SECURED},
        "/orders/{id}": {"get": SECURED},
        "/auth/token": {"post": OPEN},  # a login without a declared body
        "/auth/login": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Login"}}
                    }
                },
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}


@pytest.fixture(scope="module")
def server() -> Iterator[LocalServer]:
    with LocalServer(SERVER_APP) as running:
        yield running


@pytest.fixture(autouse=True)
def nothing_seen() -> None:
    SEEN.clear()


@pytest.fixture
def app(app: FastAPI) -> FastAPI:
    """The project's host does not resolve for the platform (as in the verification tests); only
    the prober reaches the local server, with loopback allowed on top of the production policy."""
    app.state.identity_prober = IdentityProber(
        resolver=ScriptedResolver([LOOPBACK]), address_policy=allow_loopback
    )
    return app


@pytest.fixture
def cipher(app: FastAPI) -> CredentialCipher:
    result: CredentialCipher = app.state.credential_cipher
    return result


class Project:
    """A project of `analyst`, on the local server, with the contract above."""

    def __init__(self, analyst: Analyst, data: dict[str, Any]) -> None:
        self.analyst = analyst
        self.id: str = data["id"]
        self.operations: dict[str, str] = {}

    @property
    def path(self) -> str:
        return f"/projects/{self.id}/identities"

    async def request(self, method: str, suffix: str = "", **kwargs: Any) -> Any:
        return await self.analyst.request(method, self.path + suffix, **kwargs)

    async def create(self, **fields: Any) -> dict[str, Any]:
        response = await self.request("POST", json=identity_body(**fields))
        assert response.status_code == 201, response.text
        result: dict[str, Any] = response.json()
        return result

    async def import_contract(self) -> None:
        files = {"file": ("openapi.json", json.dumps(CONTRACT).encode(), "application/json")}
        response = await self.analyst.request("POST", f"/projects/{self.id}/contracts", files=files)
        assert response.status_code == 201, response.text
        listed = await self.analyst.request("GET", f"/projects/{self.id}/operations")
        self.operations = {f"{o['method']} {o['path']}": o["id"] for o in listed.json()["items"]}

    async def verify(self) -> None:
        response = await self.analyst.request(
            "POST", f"/projects/{self.id}/verification", json={"method": "dns"}
        )
        assert response.status_code == 200, response.text


def identity_body(**fields: Any) -> dict[str, Any]:
    return {
        "name": "Usuario A",
        "role": "user",
        "auth_type": "bearer",
        "credential": {"token": TOKEN},
        **fields,
    }


async def new_project(analyst: Analyst, server: LocalServer, *, ready: bool = True) -> Project:
    project = Project(analyst, await analyst.create(base_url=f"http://{HOST}:{server.port}/v1"))
    if ready:
        await project.import_contract()
        await project.verify()
    return project


@pytest.fixture
async def project(ana: Analyst, server: LocalServer) -> Project:
    return await new_project(ana, server)


async def stored(owner: AsyncEngine, identity_id: str) -> Identity:
    async with AsyncSession(owner) as db:
        row = await db.get(Identity, uuid.UUID(identity_id))
        assert row is not None
        return row


def assert_no_secret(payload: str) -> None:
    for secret in (TOKEN, PASSWORD, TOKEN[:-4]):
        assert secret not in payload


# ------------------------------------------------------------------ list and create


async def test_a_new_project_lists_only_the_anonymous_identity(project: Project) -> None:
    response = await project.request("GET")
    assert response.status_code == 200
    body = response.json()
    assert (body["total"], body["page"], body["page_size"]) == (1, 1, 20)
    anonymous = body["items"][0]
    assert anonymous["auth_type"] == "none"
    assert anonymous["credential_suffix"] is None
    assert anonymous["warnings"] == []  # it cannot own resources: nothing to warn about


async def test_create_a_bearer_identity(project: Project, owner: AsyncEngine) -> None:
    response = await project.request("POST", json=identity_body(role_label="  vendedor "))
    assert response.status_code == 201
    body = response.json()
    assert response.headers["location"] == f"{project.path}/{body['id']}"
    assert body["name"] == "Usuario A"
    assert body["role_label"] == "vendedor"
    assert body["credential_suffix"] == "9f2a"
    assert body["status"] == "active"
    assert body["login_operation"] is None
    assert body["last_tested_at"] is None
    assert [w["code"] for w in body["warnings"]] == ["identity.no_resources"]
    assert "credential" not in body
    assert_no_secret(response.text)

    listed = (await project.request("GET")).json()
    assert [i["auth_type"] for i in listed["items"]] == ["none", "bearer"]  # anonymous first


async def test_the_credential_is_stored_encrypted_and_bound_to_its_row(
    project: Project, owner: AsyncEngine, cipher: CredentialCipher
) -> None:
    body = await project.create()
    row = await stored(owner, body["id"])
    assert row.encrypted_credential is not None
    assert TOKEN.encode() not in row.encrypted_credential
    assert row.key_version == 1
    assert cipher.decrypt(row.id, row.encrypted_credential) == Credential(token=TOKEN)


async def test_each_kind_of_credential(project: Project) -> None:
    login = project.operations["POST /auth/login"]
    cases = [
        {"auth_type": "cookie", "credential": {"value": TOKEN}, "field_name": "sesion"},
        {"auth_type": "header", "credential": {"value": TOKEN}, "field_name": "X-Api-Key"},
        {
            "auth_type": "login",
            "credential": {"username": "ana@ejemplo.com", "password": PASSWORD},
            "login_operation_id": login,
        },
    ]
    for number, case in enumerate(cases):
        response = await project.request("POST", json=identity_body(name=f"I{number}", **case))
        assert response.status_code == 201, response.text
        assert_no_secret(response.text)
    created = (await project.request("GET")).json()["items"][1:]
    assert [i["credential_suffix"] for i in created] == ["9f2a", "9f2a", ".com"]
    assert created[2]["login_operation"] == {
        "id": login,
        "method": "POST",
        "path": "/auth/login",
    }


async def test_login_and_bearer_do_not_keep_a_field_name(project: Project) -> None:
    body = await project.create(field_name="X-Sobra")
    assert body["field_name"] is None


@pytest.mark.parametrize(
    ("fields", "code"),
    [
        ({"credential": {"value": TOKEN}}, "identity.credential_mismatch"),
        ({"auth_type": "login", "credential": {"token": "x"}}, "identity.credential_mismatch"),
        ({"auth_type": "cookie", "credential": {"value": "x"}}, "identity.field_name_required"),
        (
            {"auth_type": "header", "credential": {"value": "x"}, "field_name": "Host"},
            "identity.field_name_reserved",
        ),
        (
            {"auth_type": "header", "credential": {"value": "x"}, "field_name": "cookie"},
            "identity.field_name_reserved",
        ),
        (
            {"auth_type": "login", "credential": {"username": "a", "password": "b"}},
            "identity.login_operation_required",
        ),
        (
            {
                "auth_type": "login",
                "credential": {"username": "a", "password": "b"},
                "login_operation_id": str(uuid.uuid4()),
            },
            "identity.login_operation_required",
        ),
    ],
)
async def test_rules_of_the_credential(project: Project, fields: dict[str, Any], code: str) -> None:
    response = await project.request("POST", json=identity_body(**fields))
    assert response.status_code == 422, response.text
    assert response.json()["code"] == code
    assert_no_secret(response.text)


@pytest.mark.parametrize(
    "body",
    [
        identity_body(auth_type="none", credential={"token": "x"}),  # the anonymous kind
        identity_body(credential={"token": "x", "value": "y"}),
        identity_body(credential={"token": ""}),
        identity_body(credential={"token": "con\nsalto"}),
        identity_body(name="   "),
        identity_body(field_name="con espacio"),
        {k: v for k, v in identity_body().items() if k != "credential"},
    ],
)
async def test_malformed_bodies(project: Project, body: dict[str, Any]) -> None:
    response = await project.request("POST", json=body)
    assert response.status_code == 422
    assert response.json()["code"].startswith("validation.")
    assert_no_secret(response.text)


async def test_names_are_unique_among_live_identities(project: Project) -> None:
    await project.create()
    response = await project.request("POST", json=identity_body(name=" Usuario A "))
    assert (response.status_code, response.json()["code"]) == (409, "identity.name_taken")


async def test_at_most_twenty_identities_counting_the_anonymous_one(project: Project) -> None:
    for number in range(19):
        await project.create(name=f"Usuario {number}")
    response = await project.request("POST", json=identity_body(name="La vigésima primera"))
    assert (response.status_code, response.json()["code"]) == (409, "identity.limit_reached")
    page = (await project.request("GET", params={"page": 2, "page_size": 15})).json()
    assert (page["total"], len(page["items"])) == (20, 5)


# ------------------------------------------------------------------ update


async def test_a_new_credential_replaces_the_old_one(
    project: Project, owner: AsyncEngine, cipher: CredentialCipher
) -> None:
    created = await project.create()
    before = (await stored(owner, created["id"])).encrypted_credential
    response = await project.request(
        "PATCH", f"/{created['id']}", json={"credential": {"token": "otro-token-ABCD"}}
    )
    assert response.status_code == 200, response.text
    assert response.json()["credential_suffix"] == "ABCD"
    row = await stored(owner, created["id"])
    assert row.encrypted_credential != before
    assert row.encrypted_credential is not None
    assert cipher.decrypt(row.id, row.encrypted_credential).token == "otro-token-ABCD"


async def test_changing_the_kind_needs_the_new_credential(project: Project) -> None:
    created = await project.create()
    path = f"/{created['id']}"
    response = await project.request("PATCH", path, json={"auth_type": "cookie"})
    assert response.json()["code"] == "identity.credential_required"
    response = await project.request(
        "PATCH", path, json={"auth_type": "cookie", "credential": {"value": "galleta-1234"}}
    )
    assert response.json()["code"] == "identity.field_name_required"
    response = await project.request(
        "PATCH",
        path,
        json={"auth_type": "cookie", "credential": {"value": "galleta-1234"}, "field_name": "s"},
    )
    assert response.status_code == 200
    assert (response.json()["auth_type"], response.json()["field_name"]) == ("cookie", "s")


async def test_edit_name_role_and_label(project: Project) -> None:
    created = await project.create()
    other = await project.create(name="Usuario B")
    path = f"/{created['id']}"
    response = await project.request(
        "PATCH", path, json={"name": "Administradora", "role": "admin", "role_label": None}
    )
    assert response.status_code == 200
    body = response.json()
    assert (body["name"], body["role"], body["role_label"]) == ("Administradora", "admin", None)
    assert body["credential_suffix"] == "9f2a"  # untouched
    clash = await project.request("PATCH", path, json={"name": other["name"]})
    assert clash.json()["code"] == "identity.name_taken"
    same = await project.request("PATCH", path, json={"name": "Administradora"})
    assert same.status_code == 200  # its own name is not a clash
    empty = await project.request("PATCH", path, json={})
    assert empty.json()["code"] == "validation.failed"


async def test_the_anonymous_identity_cannot_be_touched(project: Project) -> None:
    anonymous = (await project.request("GET")).json()["items"][0]["id"]
    for method, suffix, body in (
        ("PATCH", f"/{anonymous}", {"name": "Otra"}),
        ("DELETE", f"/{anonymous}", None),
        ("POST", f"/{anonymous}/test", None),
    ):
        response = await project.request(method, suffix, json=body)
        assert (response.status_code, response.json()["code"]) == (409, "identity.anonymous")


# ------------------------------------------------------------------ delete


async def _open_finding(owner: AsyncEngine, project_id: str, identity_id: str) -> uuid.UUID:
    async with AsyncSession(owner) as db, db.begin():
        run = Run(
            project_id=uuid.UUID(project_id),
            number=1,
            config={"modules": ["configuration"]},
            status="completed",
            end_reason="normal",
            finished_at=text("now()"),
        )
        metric = FindingMetric(
            week=date(2026, 11, 2), module="configuration", owasp_category="API8", severity="low"
        )
        db.add_all([run, metric])
        await db.flush()
        finding = Finding(
            project_id=run.project_id,
            module="configuration",
            finding_type="configuration.missing_header.hsts",
            identity_id=uuid.UUID(identity_id),
            severity="low",
            owasp_category="API8",
            title="Falta HSTS",
            recommendation="Envía Strict-Transport-Security.",
            status="persistent",
            first_run_id=run.id,
            last_run_id=run.id,
            metric_id=metric.id,
        )
        resource = Resource(
            project_id=run.project_id,
            identity_id=uuid.UUID(identity_id),
            resource_type="pedido",
            value="101",
            source="manual",
        )
        db.add_all([finding, resource])
        await db.flush()
        return finding.id


async def test_delete_erases_the_credential_and_frees_the_name(
    ana: Analyst, project: Project, owner: AsyncEngine
) -> None:
    created = await project.create()
    finding_id = await _open_finding(owner, project.id, created["id"])
    listed = (await project.request("GET")).json()["items"][1]
    assert (listed["resource_count"], listed["warnings"]) == (1, [])

    response = await project.request("DELETE", f"/{created['id']}")
    assert response.status_code == 204

    row = await stored(owner, created["id"])
    assert (row.encrypted_credential, row.key_version, row.credential_suffix) == (None, None, None)
    assert row.deleted_at is not None
    async with AsyncSession(owner) as db:
        resources = await db.scalars(select(Resource).where(Resource.identity_id == row.id))
        assert list(resources) == []
        finding = await db.get(Finding, finding_id)
        assert finding is not None
        assert (finding.status, finding.resolution_reason) == ("resolved", "identity_deleted")
        assert finding.resolved_at is not None
        events = list(
            await db.scalars(select(FindingEvent).where(FindingEvent.finding_id == finding_id))
        )
        assert [(e.from_status, e.to_status, e.reason) for e in events] == [
            ("persistent", "resolved", "identity_deleted")
        ]
        assert events[0].user_id is not None and events[0].run_id is None

    assert (await project.request("GET")).json()["total"] == 1
    assert (await project.request("DELETE", f"/{created['id']}")).status_code == 404
    again = await project.request("POST", json=identity_body())  # the name is free
    assert again.status_code == 201


async def test_no_delete_while_a_run_is_active(project: Project, owner: AsyncEngine) -> None:
    created = await project.create()
    async with AsyncSession(owner) as db, db.begin():
        db.add(
            Run(project_id=uuid.UUID(project.id), number=1, config={"modules": ["configuration"]})
        )
    response = await project.request("DELETE", f"/{created['id']}")
    assert (response.status_code, response.json()["code"]) == (409, "project.active_run")


# ------------------------------------------------------------------ test (RF-32)


async def test_a_working_bearer_token(project: Project, owner: AsyncEngine) -> None:
    created = await project.create()
    response = await project.request("POST", f"/{created['id']}/test")
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["succeeded"], body["status_code"], body["failure"]) == (True, 200, None)
    assert body["operation"] == {
        "id": project.operations["GET /me"],
        "method": "GET",
        "path": "/me",
    }
    assert SEEN[0]["headers"]["authorization"] == f"Bearer {TOKEN}"
    assert_no_secret(response.text)

    identity = (await project.request("GET")).json()["items"][1]
    assert (identity["last_test_status_code"], identity["last_tested_at"]) == (
        200,
        body["tested_at"],
    )


async def test_a_rejected_token_reports_the_status(project: Project) -> None:
    created = await project.create(credential={"token": "token-equivocado"})
    order_list = project.operations["GET /orders"]
    response = await project.request(
        "POST", f"/{created['id']}/test", json={"operation_id": order_list}
    )
    body = response.json()
    assert (body["succeeded"], body["status_code"], body["failure"]) == (False, 401, "rejected")
    assert body["operation"]["path"] == "/orders"


async def test_automatic_login(project: Project) -> None:
    created = await project.create(
        auth_type="login",
        credential={"username": "ana@ejemplo.com", "password": PASSWORD},
        login_operation_id=project.operations["POST /auth/login"],
    )
    response = await project.request("POST", f"/{created['id']}/test")
    body = response.json()
    assert (body["succeeded"], body["status_code"]) == (True, 200), body
    # The field names come from the referenced `Login` schema of the contract.
    assert SEEN[0]["body"] == {"correo": "ana@ejemplo.com", "clave": PASSWORD}
    assert_no_secret(response.text)


async def test_a_failed_login(project: Project) -> None:
    created = await project.create(
        auth_type="login",
        credential={"username": "ana@ejemplo.com", "password": "mala"},
        login_operation_id=project.operations["POST /auth/login"],
    )
    body = (await project.request("POST", f"/{created['id']}/test")).json()
    assert (body["status_code"], body["failure"]) == (401, "login_failed")


async def test_an_expired_identity_becomes_active_when_it_works(
    project: Project, owner: AsyncEngine
) -> None:
    created = await project.create()
    async with owner.begin() as connection:
        await connection.execute(
            text("UPDATE identities SET status = 'expired_credential' WHERE id = :id"),
            {"id": created["id"]},
        )
    await project.request("POST", f"/{created['id']}/test")
    assert (await stored(owner, created["id"])).status == "active"


@pytest.mark.parametrize("operation", ["POST /orders", "GET /orders/{id}", "missing", "retired"])
async def test_the_chosen_operation_must_be_a_live_get(
    project: Project, owner: AsyncEngine, operation: str
) -> None:
    created = await project.create()
    if operation == "missing":
        operation_id = str(uuid.uuid4())
    elif operation == "retired":
        operation_id = project.operations["GET /public"]
        async with owner.begin() as connection:
            await connection.execute(
                text("UPDATE operations SET retired_at = now() WHERE id = :id"),
                {"id": operation_id},
            )
    else:
        operation_id = project.operations[operation]
    response = await project.request(
        "POST", f"/{created['id']}/test", json={"operation_id": operation_id}
    )
    assert response.status_code == 422
    assert response.json()["code"] == "identity.no_test_operation"


async def test_without_a_protected_get_there_is_nothing_to_test(
    ana: Analyst, server: LocalServer
) -> None:
    project = await new_project(ana, server, ready=False)
    await project.verify()
    created = await project.create()
    response = await project.request("POST", f"/{created['id']}/test")
    assert response.json()["code"] == "identity.no_test_operation"


async def test_an_unverified_project_sends_nothing(ana: Analyst, server: LocalServer) -> None:
    """RN-01: no request reaches an API whose ownership is not verified."""
    project = await new_project(ana, server, ready=False)
    await project.import_contract()
    created = await project.create()
    response = await project.request("POST", f"/{created['id']}/test")
    assert (response.status_code, response.json()["code"]) == (409, "project.not_verified")
    assert SEEN == []


async def test_a_login_operation_retired_later(project: Project, owner: AsyncEngine) -> None:
    login = project.operations["POST /auth/login"]
    created = await project.create(
        auth_type="login",
        credential={"username": "ana@ejemplo.com", "password": PASSWORD},
        login_operation_id=login,
    )
    async with owner.begin() as connection:
        await connection.execute(
            text("UPDATE operations SET retired_at = now() WHERE id = :id"), {"id": login}
        )
    response = await project.request("POST", f"/{created['id']}/test")
    assert (response.status_code, response.json()["code"]) == (
        422,
        "identity.login_operation_required",
    )
    assert SEEN == []


# ------------------------------------------------------------------ isolation (RN-02)


async def test_another_analysts_identities_do_not_exist(
    project: Project, new_analyst: Any, server: LocalServer
) -> None:
    created = await project.create()
    intruder: Analyst = new_analyst()
    await intruder.accept_terms()
    base = f"/projects/{project.id}/identities"
    for method, path, body in (
        ("GET", base, None),
        ("POST", base, identity_body(name="Intrusa")),
        ("PATCH", f"{base}/{created['id']}", {"name": "Intrusa"}),
        ("DELETE", f"{base}/{created['id']}", None),
        ("POST", f"{base}/{created['id']}/test", None),
    ):
        response = await intruder.request(method, path, json=body)
        assert response.status_code == 404, (method, path)
        assert response.json()["code"] == "resource.not_found"
    assert SEEN == []

    # Their own project does not reach this identity either.
    theirs = await new_project(intruder, server, ready=False)
    response = await theirs.request("PATCH", f"/{created['id']}", json={"name": "Intrusa"})
    assert response.status_code == 404


# ------------------------------------------------------------------ never in the logs (RN-11)


async def test_the_credential_never_reaches_the_logs(
    project: Project, monkeypatch: pytest.MonkeyPatch
) -> None:
    with structlog.testing.capture_logs() as logs:
        # A logger cached before capture_logs would bypass it.
        monkeypatch.setattr(identities_service, "log", structlog.get_logger("test"))
        created = await project.create(
            auth_type="login",
            credential={"username": "ana@ejemplo.com", "password": PASSWORD},
            login_operation_id=project.operations["POST /auth/login"],
        )
        await project.request(
            "PATCH",
            f"/{created['id']}",
            json={"credential": {"username": "ana@ejemplo.com", "password": PASSWORD + "2"}},
        )
        await project.request("POST", f"/{created['id']}/test")
        await project.request("DELETE", f"/{created['id']}")
    events = [entry["event"] for entry in logs]
    assert {"identity_created", "identity_updated", "identity_tested", "identity_deleted"} <= set(
        events
    )
    assert_no_secret(repr(logs))


async def test_a_login_without_a_declared_body_uses_the_usual_names(project: Project) -> None:
    created = await project.create(
        auth_type="login",
        credential={"username": "ana@ejemplo.com", "password": PASSWORD},
        login_operation_id=project.operations["POST /auth/token"],
    )
    body = (await project.request("POST", f"/{created['id']}/test")).json()
    assert body["failure"] == "login_failed"
    assert SEEN == []  # /auth/token does not exist on the local server: a 404 before any login


async def test_an_unreadable_credential_is_an_internal_error(
    project: Project, owner: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lost key or a tampered row: a 500 without detail, never the analyst's fault (RNF-07)."""
    created = await project.create()
    async with owner.begin() as connection:
        await connection.execute(
            text(
                "UPDATE identities SET encrypted_credential ="
                " overlay(encrypted_credential placing '\\xff'::bytea from 20 for 1)"
                " WHERE id = :id"
            ),
            {"id": created["id"]},
        )
    with structlog.testing.capture_logs() as logs:
        monkeypatch.setattr(identities_service, "log", structlog.get_logger("test"))
        response = await project.request("POST", f"/{created['id']}/test")
    assert (response.status_code, response.json()["code"]) == (500, "internal")
    assert "identity_credential_unreadable" in [entry["event"] for entry in logs]
    assert SEEN == []
    assert_no_secret(response.text)
