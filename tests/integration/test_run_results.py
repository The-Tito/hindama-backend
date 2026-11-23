"""`GET /projects/{project_id}/runs/{run_id}/results`: the identity × operation matrix (CU-15,
RF-64, RN-02).

The cells are written here as the scanner writes them (one row per finished cell); the scanner tests
check which cells each module produces.
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.models import Identity, Result, Run
from tests.integration.conftest import Analyst
from tests.integration.test_runs import Project, new_project, owner_session, start

CONTRACT = {
    "openapi": "3.1.0",
    "info": {"title": "API de pedidos", "version": "1"},
    "paths": {
        "/users": {"get": {"responses": {"200": {"description": "Usuarios"}}}},
        "/orders": {
            "get": {"responses": {"200": {"description": "Pedidos"}}},
            "post": {"responses": {"201": {"description": "Creado"}}},
        },
    },
}


class Matrix:
    """A launched run of a project with a contract, and the ids its cells refer to."""

    def __init__(self, project: Project, run_id: str) -> None:
        self.project = project
        self.run_id = run_id
        self.operations: dict[tuple[str, str], str] = {}
        self.identities: dict[str, str] = {}

    @property
    def url(self) -> str:
        return f"{self.project.runs}/{self.run_id}/results"

    async def get(self, query: str = "", analyst: Analyst | None = None) -> Any:
        return await (analyst or self.project.analyst).request("GET", f"{self.url}{query}")


async def new_matrix(analyst: Analyst, owner: AsyncEngine) -> Matrix:
    project = await new_project(analyst)
    files = {"file": ("openapi.json", json.dumps(CONTRACT).encode(), "application/json")}
    response = await analyst.request("POST", f"/projects/{project.id}/contracts", files=files)
    assert response.status_code == 201, response.text
    launched = await project.launch()
    assert launched.status_code == 202, launched.text
    matrix = Matrix(project, launched.json()["id"])

    operations = (await analyst.request("GET", f"/projects/{project.id}/operations")).json()
    matrix.operations = {(item["method"], item["path"]): item["id"] for item in operations["items"]}
    async with await owner_session(owner) as db, db.begin():
        for name, deleted in (("Cliente B", False), ("Cliente A", False), ("Cliente C", True)):
            identity = Identity(
                project_id=UUID(project.id),
                name=name,
                role="user",
                auth_type="bearer",
                deleted_at=func.now() if deleted else None,
            )
            if not deleted:
                identity.encrypted_credential = b"\x01" * 40
                identity.key_version = 1
                identity.credential_suffix = "abcd"
            db.add(identity)
            await db.flush()
            matrix.identities[name] = str(identity.id)
    identities = (await analyst.request("GET", f"/projects/{project.id}/identities")).json()
    anonymous = next(item for item in identities["items"] if item["auth_type"] == "none")
    matrix.identities["Anónimo"] = anonymous["id"]
    return matrix


async def add_cells(owner: AsyncEngine, matrix: Matrix, cells: list[tuple[Any, ...]]) -> None:
    """`(module, (method, path) | None, identity name, expected, observed, verdict)`."""
    async with await owner_session(owner) as db, db.begin():
        for module, operation, identity, expected, observed, verdict in cells:
            db.add(
                Result(
                    project_id=UUID(matrix.project.id),
                    run_id=UUID(matrix.run_id),
                    module=module,
                    operation_id=None if operation is None else UUID(matrix.operations[operation]),
                    identity_id=UUID(matrix.identities[identity]),
                    expected=expected,
                    observed=observed,
                    verdict=verdict,
                )
            )


# Written in no particular order; the endpoint sorts them.
CELLS = [
    ("object_access", ("GET", "/users"), "Cliente B", "denied", "200 allowed", "fail"),
    ("configuration", None, "Anónimo", "no_cors_wildcard", "cors_wildcard", "fail"),
    (
        "object_access",
        ("GET", "/orders"),
        "Cliente B",
        "own_data_only",
        "200 own_data_only",
        "pass",
    ),
    ("configuration", ("GET", "/users"), "Anónimo", "hsts", "hsts", "pass"),
    (
        "object_access",
        ("GET", "/orders"),
        "Cliente A",
        "own_data_only",
        "200 own_data_only",
        "pass",
    ),
    ("object_access", ("POST", "/orders"), "Cliente A", "allowed", "no_response", "error"),
    ("authentication", ("GET", "/users"), "Cliente C", "denied", "expired", "skipped"),
]


def keys(body: dict[str, Any]) -> list[tuple[str, str | None, str | None, str]]:
    return [
        (
            item["module"],
            None if item["operation"] is None else item["operation"]["method"],
            None if item["operation"] is None else item["operation"]["path"],
            item["identity"]["name"],
        )
        for item in body["items"]
    ]


@pytest.fixture
async def matrix(ana: Analyst, owner: AsyncEngine) -> Matrix:
    created = await new_matrix(ana, owner)
    await add_cells(owner, created, CELLS)
    return created


# ------------------------------------------------------------------ the matrix (RF-64)


async def test_cells_come_in_catalog_order(matrix: Matrix) -> None:
    response = await matrix.get()

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == len(CELLS)
    assert (body["page"], body["page_size"]) == (1, 100)
    assert keys(body) == [
        ("authentication", "GET", "/users", "Cliente C"),
        ("configuration", None, None, "Anónimo"),  # API-wide checks first in their module
        ("configuration", "GET", "/users", "Anónimo"),
        ("object_access", "GET", "/orders", "Cliente A"),
        ("object_access", "GET", "/orders", "Cliente B"),
        ("object_access", "POST", "/orders", "Cliente A"),
        ("object_access", "GET", "/users", "Cliente B"),
    ]


async def test_a_cell_has_what_was_expected_observed_and_the_verdict(matrix: Matrix) -> None:
    body = (await matrix.get("?verdict=fail&module=object_access")).json()

    [cell] = body["items"]
    evaluated_at = cell.pop("evaluated_at")
    assert datetime.fromisoformat(evaluated_at) <= datetime.now(UTC)
    assert cell == {
        "module": "object_access",
        "operation": {
            "id": matrix.operations[("GET", "/users")],
            "method": "GET",
            "path": "/users",
        },
        "identity": {"id": matrix.identities["Cliente B"], "name": "Cliente B", "deleted": False},
        "expected": "denied",
        "observed": "200 allowed",
        "verdict": "fail",
    }


async def test_a_deleted_identity_keeps_its_cells(matrix: Matrix) -> None:
    body = (await matrix.get(f"?identity_id={matrix.identities['Cliente C']}")).json()

    assert [item["identity"] for item in body["items"]] == [
        {"id": matrix.identities["Cliente C"], "name": "Cliente C", "deleted": True}
    ]


async def test_filters(matrix: Matrix) -> None:
    orders = matrix.operations[("GET", "/orders")]

    two_modules = (await matrix.get("?module=configuration&module=authentication")).json()
    not_evaluated = (await matrix.get("?verdict=skipped&verdict=error")).json()
    one_operation = (await matrix.get(f"?operation_id={orders}")).json()
    combined = (
        await matrix.get(f"?operation_id={orders}&identity_id={matrix.identities['Cliente A']}")
    ).json()
    unknown = (await matrix.get(f"?identity_id={uuid.uuid4()}")).json()

    assert two_modules["total"] == 3
    assert [item["verdict"] for item in not_evaluated["items"]] == ["skipped", "error"]
    assert keys(one_operation) == [
        ("object_access", "GET", "/orders", "Cliente A"),
        ("object_access", "GET", "/orders", "Cliente B"),
    ]
    assert combined["total"] == 1
    assert unknown == {"items": [], "total": 0, "page": 1, "page_size": 100}


async def test_pages_do_not_overlap(matrix: Matrix) -> None:
    pages = [(await matrix.get(f"?page={page}&page_size=3")).json() for page in (1, 2, 3, 4)]

    seen = [key for body in pages for key in keys(body)]
    assert [len(body["items"]) for body in pages] == [3, 3, 1, 0]
    assert {body["total"] for body in pages} == {len(CELLS)}
    assert seen == keys((await matrix.get()).json())


@pytest.mark.parametrize(
    "query",
    [
        "?module=object_access&module=object_access",
        "?verdict=fail&verdict=fail",
        "?module=sql",
        "?verdict=passed",
        "?page_size=501",
        "?page_size=0",
        "?page=0",
        "?identity_id=ana",
    ],
)
async def test_invalid_queries(matrix: Matrix, query: str) -> None:
    response = await matrix.get(query)

    assert response.status_code == 422, response.text


async def test_an_active_run_shows_the_cells_finished_so_far(
    ana: Analyst, owner: AsyncEngine
) -> None:
    created = await new_matrix(ana, owner)

    queued = (await created.get()).json()
    await start(owner, created.run_id)
    await add_cells(owner, created, CELLS[:2])
    running = (await created.get()).json()

    assert queued == {"items": [], "total": 0, "page": 1, "page_size": 100}
    assert running["total"] == 2


async def test_cells_of_other_runs_are_not_shown(matrix: Matrix, owner: AsyncEngine) -> None:
    async with await owner_session(owner) as db, db.begin():
        run = await db.get(Run, UUID(matrix.run_id))
        assert run is not None
        run.status, run.end_reason = "completed", "normal"
        run.started_at = run.finished_at = func.now()
    second = (await matrix.project.launch()).json()
    other = Matrix(matrix.project, second["id"])
    other.operations, other.identities = matrix.operations, matrix.identities
    await add_cells(owner, other, CELLS[:1])

    assert (await matrix.get()).json()["total"] == len(CELLS)
    assert (await other.get()).json()["total"] == 1


# ------------------------------------------------------------------ isolation (RN-02)


async def test_the_matrix_of_another_analyst_or_project_is_not_found(
    matrix: Matrix, ana: Analyst, new_analyst: Any
) -> None:
    sibling = await new_project(ana)
    other: Analyst = new_analyst()
    await other.accept_terms()

    from_other = await matrix.get(analyst=other)
    from_sibling = await ana.request("GET", f"{sibling.runs}/{matrix.run_id}/results")
    missing = await ana.request("GET", f"{matrix.project.runs}/{uuid.uuid4()}/results")

    assert from_other.status_code == from_sibling.status_code == missing.status_code == 404
    assert from_other.json()["code"] == "resource.not_found"
