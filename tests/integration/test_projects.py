"""`/projects` (CU-05, CU-06; RF-10 to RF-16, RN-02, RN-12), against PostgreSQL as `hindama_api`.

Data the API cannot create yet (contracts, identities, runs, findings) is inserted as the schema
owner, which RLS does not filter.
"""

import ipaddress
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import (
    ContractVersion,
    DailyMetric,
    Finding,
    FindingMetric,
    Identity,
    Operation,
    Project,
    Resource,
    Run,
    User,
)
from hindama.models.base import new_id
from hindama.models.enums import DailyMetricName
from tests.dns import FakeResolver
from tests.tokens import ADMIN_GROUP, FakeUserPool

TERMS = "2026-10-30"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
ALL_MISSING = {
    "authentication": ["project_not_verified", "no_contract"],
    "configuration": ["project_not_verified"],
    "object_access": [
        "project_not_verified",
        "no_contract",
        "insufficient_identities",
        "no_resources",
        "policy_unconfirmed",
    ],
    "function_access": [
        "project_not_verified",
        "no_contract",
        "no_admin_identity",
        "policy_unconfirmed",
    ],
    "property_access": ["project_not_verified", "no_contract", "insufficient_identities"],
    "resource_consumption": ["project_not_verified", "no_contract"],
    "sql_injection": ["project_not_verified", "no_contract"],
}


class Analyst:
    """What Next.js sends on behalf of one Cognito user."""

    def __init__(self, client: httpx.AsyncClient, user_pool: FakeUserPool, sub: str) -> None:
        self.client = client
        self.sub = sub
        self.headers = {"Authorization": f"Bearer {user_pool.token(sub=sub)}"}

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return await self.client.request(method, path, headers=self.headers, **kwargs)

    async def accept_terms(self) -> None:
        response = await self.request("POST", "/me/terms", json={"version": TERMS})
        assert response.status_code == 200

    async def create(self, **fields: Any) -> dict[str, Any]:
        body = {"name": "API de pedidos", "base_url": "https://api.ejemplo.com/v1", **fields}
        response = await self.request("POST", "/projects", json=body)
        assert response.status_code == 201, response.text
        project: dict[str, Any] = response.json()
        return project


@pytest.fixture
async def subs(owner: AsyncEngine) -> AsyncIterator[list[str]]:
    created: list[str] = []
    yield created
    async with owner.begin() as connection:
        await connection.execute(delete(User).where(User.cognito_sub.in_(created)))


@pytest.fixture
def new_analyst(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, subs: list[str]
) -> Any:
    def make() -> Analyst:
        sub = str(new_id())
        subs.append(sub)
        return Analyst(anonymous_client, user_pool, sub)

    return make


@pytest.fixture
async def ana(new_analyst: Any) -> Analyst:
    analyst: Analyst = new_analyst()
    await analyst.accept_terms()
    return analyst


async def owner_session(owner: AsyncEngine) -> AsyncSession:
    return AsyncSession(owner, expire_on_commit=False)


def modules(project: dict[str, Any]) -> dict[str, list[str]]:
    return {m["module"]: m["missing"] for m in project["modules"]}


# ------------------------------------------------------------------ create (CU-05)


async def test_create_a_project(ana: Analyst, owner: AsyncEngine) -> None:
    async with owner.connect() as connection:
        before = await connection.scalar(
            select(DailyMetric.value).where(
                DailyMetric.date == datetime.now(UTC).date(),
                DailyMetric.metric == DailyMetricName.PROJECTS_CREATED,
            )
        )

    response = await ana.request(
        "POST",
        "/projects",
        json={
            "name": "  API interna de inventario  ",
            "description": "Entorno de staging.",
            "base_url": "HTTP://Inventario.Ejemplo.MX",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert response.headers["Location"] == f"/projects/{body['id']}"
    assert body["name"] == "API interna de inventario"
    assert body["description"] == "Entorno de staging."
    assert body["base_url"] == "http://inventario.ejemplo.mx"
    assert body["host"] == "inventario.ejemplo.mx"
    assert body["verification_status"] == "pending"
    assert body["verified_at"] is None
    assert body["concluded"] is False
    assert body["current_contract"] is None
    assert body["last_run"] is None
    assert body["open_findings_by_severity"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 0,
    }
    assert modules(body) == ALL_MISSING
    assert [m["risk"] for m in body["modules"]] == [
        "low",
        "low",
        "low",
        "low",
        "medium",
        "high",
        "high",
    ]
    assert all(m["available"] is False for m in body["modules"])
    assert [w["code"] for w in body["warnings"]] == ["url.no_tls"]

    async with owner.connect() as connection:
        project = (
            await connection.execute(select(Project).where(Project.id == UUID(body["id"])))
        ).one()
        identities = (
            await connection.execute(
                select(Identity.auth_type, Identity.role).where(Identity.project_id == project.id)
            )
        ).all()
        after = await connection.scalar(
            select(DailyMetric.value).where(
                DailyMetric.date == datetime.now(UTC).date(),
                DailyMetric.metric == DailyMetricName.PROJECTS_CREATED,
            )
        )
    assert len(project.verification_code) == 32
    assert identities == [("none", "other")]  # the anonymous identity (RF-34)
    assert after == (before or 0) + 1


async def test_https_has_no_warning_and_description_is_optional(ana: Analyst) -> None:
    body = await ana.create(description="   ")

    assert body["warnings"] == []
    assert body["description"] is None


async def test_terms_are_required(new_analyst: Any, owner: AsyncEngine) -> None:
    analyst: Analyst = new_analyst()

    response = await analyst.request(
        "POST", "/projects", json={"name": "API", "base_url": "https://api.ejemplo.com"}
    )

    assert response.status_code == 403
    assert response.json()["code"] == "terms.not_accepted"


async def test_terms_of_an_older_version_are_not_enough(ana: Analyst, app: FastAPI) -> None:
    app.state.settings = app.state.settings.model_copy(update={"terms_version": "2026-12-01"})

    response = await ana.request(
        "POST", "/projects", json={"name": "API", "base_url": "https://api.ejemplo.com"}
    )

    assert response.json()["code"] == "terms.not_accepted"


async def test_the_administrator_cannot_use_projects(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, subs: list[str]
) -> None:
    sub = str(new_id())
    subs.append(sub)
    headers = {"Authorization": f"Bearer {user_pool.token(sub=sub, groups=[ADMIN_GROUP])}"}
    project_path = f"/projects/{new_id()}"

    responses = [
        await anonymous_client.get("/projects", headers=headers),
        await anonymous_client.post(
            "/projects", headers=headers, json={"name": "A", "base_url": "https://a.com"}
        ),
        await anonymous_client.get(project_path, headers=headers),
        await anonymous_client.patch(project_path, headers=headers, json={"name": "B"}),
        await anonymous_client.delete(f"{project_path}?confirmation=A", headers=headers),
    ]

    assert [r.status_code for r in responses] == [403] * 5
    assert {r.json()["code"] for r in responses} == {"role.forbidden"}


@pytest.mark.parametrize(
    ("base_url", "code"),
    [
        ("api.ejemplo.com", "url.invalid_format"),
        ("https://usuario:clave@api.ejemplo.com", "url.invalid_format"),
        ("https://api.ejemplo.com/#x", "url.invalid_format"),
        ("ftp://api.ejemplo.com", "url.scheme_not_allowed"),
        ("http://127.0.0.1:8000", "url.destination_not_allowed"),
        ("http://169.254.169.254/latest/meta-data/", "url.destination_not_allowed"),
        ("https://interna.ejemplo.com", "url.destination_not_allowed"),
        ("https://hindama.ejemplo.com", "url.destination_not_allowed"),
    ],
)
async def test_base_url_is_validated(
    ana: Analyst, resolver: FakeResolver, owner: AsyncEngine, base_url: str, code: str
) -> None:
    resolver.set("interna.ejemplo.com", "93.184.215.14", "10.0.0.8")
    resolver.set("hindama.ejemplo.com", "198.51.100.7")  # TEST-NET-2: never global

    response = await ana.request("POST", "/projects", json={"name": "API", "base_url": base_url})

    assert response.status_code == 422
    body = response.json()
    assert body["code"] == code
    assert body["errors"] == [
        {"field": "base_url", "code": code, "message": body["errors"][0]["message"]}
    ]
    async with owner.connect() as connection:
        count = await connection.scalar(
            select(func.count()).select_from(Project).join(User).where(User.cognito_sub == ana.sub)
        )
    assert count == 0


async def test_hindama_own_addresses_are_rejected(
    ana: Analyst, resolver: FakeResolver, app: FastAPI
) -> None:
    app.state.settings = app.state.settings.model_copy(
        update={"own_ip_addresses": [ipaddress.ip_address("8.8.4.4")]}
    )
    resolver.set("hindama.ejemplo.com", "8.8.4.4")

    response = await ana.request(
        "POST", "/projects", json={"name": "A", "base_url": "https://hindama.ejemplo.com"}
    )

    assert response.json()["code"] == "url.destination_not_allowed"


async def test_an_unresolved_host_is_accepted_with_a_momentary_warning(
    ana: Analyst, resolver: FakeResolver
) -> None:
    resolver.unresolved.add("nueva.ejemplo.com")

    created = await ana.create(base_url="https://nueva.ejemplo.com")
    later = (await ana.request("GET", f"/projects/{created['id']}")).json()

    assert [w["code"] for w in created["warnings"]] == ["url.unresolved"]
    assert later["warnings"] == []


@pytest.mark.parametrize(
    "body",
    [
        {"name": "   ", "base_url": "https://a.com"},
        {"name": "x" * 101, "base_url": "https://a.com"},
        {"name": "A", "description": "x" * 501, "base_url": "https://a.com"},
        {"name": "A", "base_url": "https://a.com/" + "x" * 2048},
        {"name": "A"},
        {"name": "A", "base_url": "https://a.com", "owner_id": str(new_id())},
        {"name": "A\u0000B", "base_url": "https://a.com"},  # was a 500 (PT-03)
        {"name": "A\u0007B", "base_url": "https://a.com"},
        {"name": "A\nB", "base_url": "https://a.com"},
        {"name": "A\u007fB", "base_url": "https://a.com"},
        {"name": "A", "description": "x\u0000y", "base_url": "https://a.com"},
        {"name": "A", "description": "x\u001by", "base_url": "https://a.com"},
    ],
)
async def test_invalid_fields(ana: Analyst, body: dict[str, Any]) -> None:
    response = await ana.request("POST", "/projects", json=body)

    assert response.status_code == 422
    assert response.json()["code"] == "validation.failed"


async def test_control_characters_are_a_format_error(ana: Analyst) -> None:
    response = await ana.request(
        "POST", "/projects", json={"name": "A\u0000B", "base_url": "https://a.com"}
    )

    assert [(e["field"], e["code"]) for e in response.json()["errors"]] == [
        ("name", "validation.format")
    ]


async def test_a_multi_line_description_is_accepted(ana: Analyst) -> None:
    description = "Primera línea\r\n\tsegunda línea"

    created = await ana.create(description=description)

    assert created["description"] == description


# ------------------------------------------------------------------ isolation (RN-02)


async def test_each_analyst_sees_only_own_projects(ana: Analyst, new_analyst: Any) -> None:
    bob: Analyst = new_analyst()
    await bob.accept_terms()
    mine = await ana.create()
    theirs = await bob.create()

    listed = (await ana.request("GET", "/projects")).json()
    foreign = f"/projects/{theirs['id']}"
    missing = f"/projects/{new_id()}"
    responses = {
        "get": await ana.request("GET", foreign),
        "patch": await ana.request("PATCH", foreign, json={"name": "Mía"}),
        "delete": await ana.request("DELETE", foreign, params={"confirmation": "API de pedidos"}),
    }
    not_found = await ana.request("GET", missing)

    assert [p["id"] for p in listed["items"]] == [mine["id"]]
    assert listed["total"] == 1
    for response in responses.values():
        assert response.status_code == 404
        body = response.json()
        # Identical to a project that does not exist, except for the request id.
        assert {k: v for k, v in body.items() if k != "request_id"} == {
            k: v for k, v in not_found.json().items() if k != "request_id"
        }
    assert (await bob.request("GET", foreign)).json()["name"] == "API de pedidos"


async def test_invalid_project_id(ana: Analyst) -> None:
    response = await ana.request("GET", "/projects/no-es-un-uuid")

    assert response.status_code == 422
    assert response.json()["code"] == "validation.failed"


# ------------------------------------------------------------------ list (RF-12)


async def test_pagination_and_sort(ana: Analyst) -> None:
    for name in ("Beta", "alfa", "Gamma"):
        await ana.create(name=name)

    first = (await ana.request("GET", "/projects", params={"page_size": 2})).json()
    second = (await ana.request("GET", "/projects", params={"page_size": 2, "page": 2})).json()
    by_name = (await ana.request("GET", "/projects", params={"sort": "name"})).json()
    beyond = (await ana.request("GET", "/projects", params={"page": 9})).json()

    assert [p["name"] for p in first["items"] + second["items"]] == ["Gamma", "alfa", "Beta"]
    assert (first["total"], first["page"], first["page_size"]) == (3, 1, 2)
    assert [p["name"] for p in by_name["items"]] == ["alfa", "Beta", "Gamma"]
    assert beyond["items"] == []
    assert beyond["total"] == 3


@pytest.mark.parametrize(
    "params",
    [
        {"page": 0},
        {"page": 10_001},
        {"page": 2**63},  # overflowed PostgreSQL's OFFSET: was a 500 (PT-03)
        {"page_size": 0},
        {"page_size": 101},
        {"sort": "owner_id"},
    ],
)
async def test_invalid_list_parameters(ana: Analyst, params: dict[str, Any]) -> None:
    response = await ana.request("GET", "/projects", params=params)

    assert response.status_code == 422
    assert response.json()["code"] == "validation.failed"


# ------------------------------------------------------------------ dashboard (RF-15)


async def seed_activity(owner: AsyncEngine, project_id: UUID) -> None:
    """A verified project with a contract, identities, resources, policies, runs and findings."""
    async with await owner_session(owner) as db, db.begin():
        project = await db.get_one(Project, project_id)
        project.verification_status = "verified"
        project.verification_method = "file"
        project.verified_at = NOW
        project.verified_host = project.host
        anonymous = await db.scalar(
            select(Identity).where(Identity.project_id == project_id, Identity.auth_type == "none")
        )
        assert anonymous is not None
        users = [
            Identity(
                project_id=project_id,
                name=f"Usuario {letter}",
                role=role,
                auth_type="bearer",
                encrypted_credential=b"\x01cipher",
                key_version=1,
                credential_suffix="9f2a",
            )
            for letter, role in (("A", "user"), ("B", "user"), ("Admin", "admin"))
        ]
        deleted = Identity(
            project_id=project_id,
            name="Borrada",
            role="admin",
            auth_type="bearer",
            deleted_at=NOW,
        )
        db.add_all([*users, deleted])
        contracts = [
            ContractVersion(
                project_id=project_id,
                number=number,
                source="file",
                format="yaml",
                openapi_version=version,
                document=b"openapi: 3.1.0",
                sha256="0" * 64,
                operation_count=count,
            )
            for number, version, count in ((1, "3.0.3", 10), (2, "3.1.0", 18))
        ]
        db.add_all(contracts)
        db.add_all(
            [
                Operation(
                    project_id=project_id,
                    method="GET",
                    normalized_path="/orders/{}",
                    path="/orders/{id}",
                    policy="owner_only",
                    owner_field="user_id",
                    confirmed_at=NOW,
                ),
                Operation(
                    project_id=project_id,
                    method="DELETE",
                    normalized_path="/users/{}",
                    path="/users/{id}",
                    policy="admin_only",
                    confirmed_at=NOW,
                    retired_at=NOW,  # retired: does not count
                ),
            ]
        )
        await db.flush()
        db.add_all(
            [
                Resource(
                    project_id=project_id,
                    identity_id=users[0].id,
                    resource_type="pedido",
                    value="101",
                    source="manual",
                ),
                Resource(
                    project_id=project_id,
                    identity_id=users[1].id,
                    resource_type="pedido",
                    value="202",
                    source="manual",
                ),
            ]
        )
        runs = [
            Run(
                project_id=project_id,
                number=1,
                config={},
                status="completed",
                end_reason="normal",
                started_at=NOW - timedelta(hours=2),
                finished_at=NOW - timedelta(hours=1),
            ),
            Run(
                project_id=project_id,
                number=2,
                config={},
                status="completed",
                end_reason="normal",
                started_at=NOW - timedelta(minutes=30),
                finished_at=NOW,
            ),
        ]
        db.add_all(runs)
        await db.flush()
        for index, (severity, status) in enumerate(
            (
                ("critical", "new"),
                ("high", "persistent"),
                ("high", "regression"),
                ("low", "resolved"),
                ("medium", "accepted_risk"),
            )
        ):
            metric = FindingMetric(
                week=date(2026, 11, 2),
                module="configuration",
                owasp_category="API8",
                severity=severity,
            )
            db.add(metric)
            await db.flush()
            db.add(
                Finding(
                    project_id=project_id,
                    module="configuration",
                    finding_type=f"configuration.test.{index}",
                    identity_id=anonymous.id,
                    severity=severity,
                    owasp_category="API8",
                    title="Prueba",
                    recommendation="Corregir.",
                    status=status,
                    dismissal_reason="accepted_risk" if status == "accepted_risk" else None,
                    justification="Aceptado." if status == "accepted_risk" else None,
                    resolution_reason="not_detected" if status == "resolved" else None,
                    resolved_at=NOW if status == "resolved" else None,
                    first_run_id=runs[0].id,
                    last_run_id=runs[1].id,
                    metric_id=metric.id,
                )
            )


async def test_dashboard_with_activity(ana: Analyst, owner: AsyncEngine) -> None:
    created = await ana.create()
    await seed_activity(owner, UUID(created["id"]))

    body = (await ana.request("GET", f"/projects/{created['id']}")).json()
    listed = (await ana.request("GET", "/projects")).json()["items"][0]

    assert body["verification_status"] == "verified"
    assert body["current_contract"]["number"] == 2
    assert body["current_contract"]["openapi_version"] == "3.1.0"
    assert body["current_contract"]["operation_count"] == 18
    assert body["last_run"]["number"] == 2
    assert body["last_run"]["status"] == "completed"
    assert body["open_findings_by_severity"] == {
        "critical": 1,
        "high": 2,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 3,
    }
    assert body["concluded"] is False
    assert modules(body) == {
        "authentication": [],
        "configuration": [],
        "object_access": [],
        "function_access": ["policy_unconfirmed"],  # its admin-only operation was retired
        "property_access": [],
        "resource_consumption": [],
        "sql_injection": [],
    }
    assert listed["open_findings"] == 3
    assert datetime.fromisoformat(listed["last_run_at"]) == NOW
    assert listed["verification_status"] == "verified"


async def test_concluded_needs_a_completed_run_and_no_open_findings(
    ana: Analyst, owner: AsyncEngine
) -> None:
    created = await ana.create()
    project_id = UUID(created["id"])
    async with await owner_session(owner) as db, db.begin():
        db.add(
            Run(
                project_id=project_id,
                number=1,
                config={},
                status="completed",
                end_reason="normal",
                finished_at=NOW,
            )
        )

    body = (await ana.request("GET", f"/projects/{created['id']}")).json()

    assert created["concluded"] is False  # no run yet
    assert body["concluded"] is True
    assert body["verification_status"] == "pending"  # independent of verification (RN-10)


# ------------------------------------------------------------------ edit (RF-13)


async def verify(owner: AsyncEngine, project_id: str) -> None:
    async with await owner_session(owner) as db, db.begin():
        project = await db.get_one(Project, UUID(project_id))
        project.verification_status = "verified"
        project.verification_method = "dns"
        project.verified_at = NOW
        project.verified_host = project.host


async def test_edit_name_and_description(ana: Analyst) -> None:
    created = await ana.create(description="Antes")
    path = f"/projects/{created['id']}"

    renamed = (await ana.request("PATCH", path, json={"name": " Nuevo nombre "})).json()
    cleared = (await ana.request("PATCH", path, json={"description": None})).json()

    assert renamed["name"] == "Nuevo nombre"
    assert renamed["description"] == "Antes"
    assert cleared["description"] is None
    assert cleared["name"] == "Nuevo nombre"
    assert datetime.fromisoformat(cleared["updated_at"]) >= datetime.fromisoformat(
        created["updated_at"]
    )


async def test_a_new_host_loses_the_verification(ana: Analyst, owner: AsyncEngine) -> None:
    created = await ana.create()
    await verify(owner, created["id"])
    path = f"/projects/{created['id']}"

    same_host = await ana.request("PATCH", path, json={"base_url": "https://api.ejemplo.com/v2"})
    new_host = await ana.request("PATCH", path, json={"base_url": "http://otra.ejemplo.com"})
    later = (await ana.request("GET", path)).json()

    assert same_host.json()["verification_status"] == "verified"
    assert same_host.json()["warnings"] == []
    body = new_host.json()
    assert body["verification_status"] == "pending"
    assert body["verified_at"] is None
    assert body["host"] == "otra.ejemplo.com"
    assert [w["code"] for w in body["warnings"]] == ["url.no_tls", "project.verification_lost"]
    assert [w["code"] for w in later["warnings"]] == ["url.no_tls"]  # momentary is gone


async def test_a_pending_project_changing_host_has_no_lost_warning(ana: Analyst) -> None:
    created = await ana.create()

    body = (
        await ana.request(
            "PATCH", f"/projects/{created['id']}", json={"base_url": "https://otra.ejemplo.com"}
        )
    ).json()

    assert body["warnings"] == []
    assert body["host"] == "otra.ejemplo.com"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({}, "validation.failed"),
        ({"base_url": None}, "validation.failed"),
        ({"name": None}, "validation.failed"),
        ({"name": ""}, "validation.failed"),
        ({"name": "A\u0000B"}, "validation.failed"),
        ({"description": "x\u0000y"}, "validation.failed"),
        ({"verification_status": "verified"}, "validation.failed"),
        ({"base_url": "http://10.0.0.1"}, "url.destination_not_allowed"),
    ],
)
async def test_invalid_edits(ana: Analyst, body: dict[str, Any], code: str) -> None:
    created = await ana.create()

    response = await ana.request("PATCH", f"/projects/{created['id']}", json=body)

    assert response.status_code == 422
    assert response.json()["code"] == code
    unchanged = (await ana.request("GET", f"/projects/{created['id']}")).json()
    assert unchanged["base_url"] == created["base_url"]


# ------------------------------------------------------------------ delete (RF-14)


async def test_delete_requires_the_exact_name(ana: Analyst) -> None:
    created = await ana.create(name="API de pedidos")
    path = f"/projects/{created['id']}"

    wrong = await ana.request("DELETE", path, params={"confirmation": "api de pedidos"})
    missing = await ana.request("DELETE", path)
    empty = await ana.request("DELETE", path, params={"confirmation": ""})
    control = await ana.request("DELETE", path, params={"confirmation": "API\u0000"})

    assert wrong.status_code == 422
    assert wrong.json()["code"] == "project.confirmation_mismatch"
    for invalid in (missing, empty, control):
        assert invalid.status_code == 422
        assert invalid.json()["code"] == "validation.failed"
    assert (await ana.request("GET", path)).status_code == 200


async def test_delete_removes_everything(ana: Analyst, owner: AsyncEngine) -> None:
    created = await ana.create()
    project_id = UUID(created["id"])
    await seed_activity(owner, project_id)

    response = await ana.request(
        "DELETE", f"/projects/{created['id']}", params={"confirmation": "API de pedidos"}
    )

    assert response.status_code == 204
    assert response.content == b""
    async with owner.connect() as connection:
        for column in (
            Project.id,
            Identity.project_id,
            ContractVersion.project_id,
            Run.project_id,
            Finding.project_id,
        ):
            count = await connection.scalar(select(func.count()).where(column == project_id))
            assert count == 0, column
    assert (await ana.request("GET", f"/projects/{created['id']}")).status_code == 404


async def test_delete_with_an_active_run_is_a_conflict(ana: Analyst, owner: AsyncEngine) -> None:
    created = await ana.create()
    async with await owner_session(owner) as db, db.begin():
        db.add(Run(project_id=UUID(created["id"]), number=1, config={}, status="running"))

    response = await ana.request(
        "DELETE", f"/projects/{created['id']}", params={"confirmation": "API de pedidos"}
    )

    assert response.status_code == 409
    assert response.json()["code"] == "project.active_run"
