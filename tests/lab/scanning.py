"""Points the scanner at the lab, and prepares a project as an analyst would, through the API.

The project's host (`api.hindama.test`) resolves to loopback only for the scanner's client, with
loopback allowed on top of the production policy (tests/servers.py).
"""

import json
from typing import Any
from uuid import UUID

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.core.credentials import CredentialCipher
from hindama.core.ownership import OwnershipChecker
from hindama.core.safe_http import SafeHttpClient
from hindama.db.session import create_session_factory
from hindama.models import Finding, Result, Run
from hindama.scanner.execution import Scanner, execute
from hindama.scanner.requester import SCAN_LIMITS
from tests.integration.conftest import Analyst
from tests.lab.app import ANA_PASSWORD, BETO_TOKEN, RAIZ_TOKEN
from tests.servers import HOST, LOOPBACK, LocalServer, ScriptedResolver, allow_loopback


def lab_scanner(
    engine: AsyncEngine, cipher: CredentialCipher, checker: OwnershipChecker
) -> Scanner:
    def http_client(host: str) -> SafeHttpClient:
        return SafeHttpClient(
            host,
            resolver=ScriptedResolver([LOOPBACK]),
            address_policy=allow_loopback,
            limits=SCAN_LIMITS,
        )

    return Scanner(
        session_factory=create_session_factory(engine),
        ownership_checker=checker,
        cipher=cipher,
        http_client=http_client,
    )


# The policy the analyst confirms for each operation (catalog, section 2.2).
POLICIES = {
    "POST /auth/login": ("public", None),
    "GET /orders": ("authenticated", None),
    "GET /orders/{order_id}": ("owner_only", "owner"),
    "DELETE /orders/{order_id}": ("owner_only", "owner"),
    "GET /invoices/{invoice_id}": ("owner_only", "owner"),
    "GET /accounts/{account_id}/statement": ("owner_or_admin", "owner"),
    "GET /reports": ("authenticated", None),
    "GET /admin/users": ("admin_only", None),
    "GET /admin/audit": ("admin_only", None),
    "DELETE /admin/users/{user_id}": ("admin_only", None),
}
RESOURCES = {
    "ana": [("orders", "ord-ana-1"), ("invoices", "inv-ana-1"), ("accounts", "acc-ana")],
    "beto": [("orders", "ord-beto-1"), ("invoices", "inv-beto-1"), ("accounts", "acc-beto")],
}


class LabProject:
    def __init__(self, analyst: Analyst, project_id: str) -> None:
        self.analyst = analyst
        self.id = project_id
        self.operations: dict[str, str] = {}  # "GET /orders" -> id
        self.identities: dict[str, str] = {}  # name -> id

    def operation(self, operation_id: UUID | None) -> str:
        return next(k for k, v in self.operations.items() if v == str(operation_id))

    def identity(self, identity_id: UUID) -> str:
        return next(k for k, v in self.identities.items() if v == str(identity_id))

    async def call(self, method: str, suffix: str, **kwargs: Any) -> Any:
        response = await self.analyst.request(method, f"/projects/{self.id}{suffix}", **kwargs)
        assert response.status_code < 300, response.text
        return response.json() if response.content else None

    async def launch(self, modules: list[str], **limits: int) -> UUID:
        body: dict[str, Any] = {"modules": modules, "limits": limits}
        created = await self.call("POST", "/runs", json=body)
        return UUID(created["id"])


async def lab_project(
    analyst: Analyst,
    server: LocalServer,
    lab: FastAPI,
    *,
    ana_password: str = ANA_PASSWORD,
    beto_token: str = BETO_TOKEN,
) -> LabProject:
    created = await analyst.create(name="Laboratorio", base_url=f"http://{HOST}:{server.port}")
    project = LabProject(analyst, created["id"])
    document = json.dumps(lab.openapi()).encode()
    files = {"file": ("openapi.json", document, "application/json")}
    await project.call("POST", "/contracts", files=files)
    listed = await project.call("GET", "/operations")
    project.operations = {f"{o['method']} {o['path']}": o["id"] for o in listed["items"]}
    await project.call("POST", "/verification", json={"method": "dns"})
    for key, (policy, owner_field) in POLICIES.items():
        await project.call(
            "PATCH",
            f"/operations/{project.operations[key]}",
            json={"policy": policy, "owner_field": owner_field},
        )
    identities: list[dict[str, Any]] = [
        {
            "name": "ana",
            "role": "user",
            "auth_type": "login",
            "credential": {"username": "ana", "password": ana_password},
            "login_operation_id": project.operations["POST /auth/login"],
        },
        {
            "name": "beto",
            "role": "user",
            "auth_type": "bearer",
            "credential": {"token": beto_token},
        },
        {
            "name": "raiz",
            "role": "admin",
            "auth_type": "bearer",
            "credential": {"token": RAIZ_TOKEN},
        },
    ]
    for body in identities:
        identity = await project.call("POST", "/identities", json=body)
        project.identities[body["name"]] = identity["id"]
    listed = await project.call("GET", "/identities")
    anonymous = next(i for i in listed["items"] if i["auth_type"] == "none")
    project.identities["anónima"] = anonymous["id"]
    for name, owned in RESOURCES.items():
        for resource_type, value in owned:
            await project.call(
                "POST",
                "/resources",
                json={
                    "identity_id": project.identities[name],
                    "resource_type": resource_type,
                    "value": value,
                },
            )
    return project


# ------------------------------------------------------------------ running and reading


async def nothing(*_: Any) -> None:
    """The job's touch: no SAQ here."""


async def run_lab(
    scanner: Scanner,
    project: LabProject,
    lab: FastAPI,
    modules: tuple[str, ...] = ("object_access",),
    **limits: int,
) -> UUID:
    lab.state.seen.clear()
    run_id = await project.launch(list(modules), **limits)
    await execute(scanner, run_id, nothing)
    return run_id


async def matrix(
    owner: AsyncEngine, project: LabProject, run_id: UUID, module: str | None = None
) -> dict[Any, Any]:
    """`(operation, identity) -> (expected, observed, verdict)` of the run's cells."""
    statement = select(Result).where(Result.run_id == run_id)
    if module is not None:
        statement = statement.where(Result.module == module)
    async with AsyncSession(owner) as db:
        rows = await db.scalars(statement)
        return {
            (project.operation(r.operation_id), project.identity(r.identity_id)): (
                r.expected,
                r.observed,
                r.verdict,
            )
            for r in rows
        }


async def findings(
    owner: AsyncEngine, project: LabProject, module: str = "object_access"
) -> dict[Any, Finding]:
    """`(operation, identity) -> finding` of one module whose cells hold one failure each."""
    return {
        key[:2]: finding for key, finding in (await typed_findings(owner, project, module)).items()
    }


async def typed_findings(
    owner: AsyncEngine, project: LabProject, module: str
) -> dict[tuple[str, str, str], Finding]:
    """`(operation, identity, finding_type) -> finding`."""
    async with AsyncSession(owner) as db:
        rows = await db.scalars(
            select(Finding).where(Finding.project_id == UUID(project.id), Finding.module == module)
        )
        return {
            (project.operation(f.operation_id), project.identity(f.identity_id), f.finding_type): f
            for f in rows
        }


async def stored_run(owner: AsyncEngine, run_id: UUID) -> Run:
    async with AsyncSession(owner) as db:
        run = await db.get(Run, run_id)
    assert run is not None
    return run
