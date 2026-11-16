"""`/projects/{project_id}/runs` (CU-12; RF-44 to RF-47, RF-63, RN-01, RN-05, RN-07).

The queue is in memory here; the scanner tests (test_scanner.py) use Redis.
"""

import json
import uuid
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.core.run_queue import RunQueue
from hindama.models import Run
from tests.integration.conftest import Analyst
from tests.queue import FailingRunQueue, MemoryRunQueue

CONTRACT = {
    "openapi": "3.1.0",
    "info": {"title": "API de pedidos", "version": "1"},
    "paths": {"/orders": {"get": {"responses": {"200": {"description": "Pedidos"}}}}},
}


async def owner_session(owner: AsyncEngine) -> AsyncSession:
    return AsyncSession(owner, expire_on_commit=False)


class Project:
    def __init__(self, analyst: Analyst, data: dict[str, Any]) -> None:
        self.analyst = analyst
        self.id: str = data["id"]

    @property
    def runs(self) -> str:
        return f"/projects/{self.id}/runs"

    async def verify(self) -> None:
        response = await self.analyst.request(
            "POST", f"/projects/{self.id}/verification", json={"method": "dns"}
        )
        assert response.status_code == 200, response.text

    async def import_contract(self) -> None:
        files = {"file": ("openapi.json", json.dumps(CONTRACT).encode(), "application/json")}
        response = await self.analyst.request("POST", f"/projects/{self.id}/contracts", files=files)
        assert response.status_code == 201, response.text

    async def launch(self, **body: Any) -> Any:
        return await self.analyst.request(
            "POST", self.runs, json={"modules": ["configuration"], **body}
        )


async def new_project(
    analyst: Analyst, *, verified: bool = True, contract: bool = False
) -> Project:
    project = Project(analyst, await analyst.create())
    if contract:
        await project.import_contract()
    if verified:
        await project.verify()
    return project


@pytest.fixture
async def project(ana: Analyst) -> Project:
    return await new_project(ana)


async def finish(owner: AsyncEngine, run_id: str, status: str = "completed") -> None:
    reasons = {"completed": "normal", "cancelled": "cancelled_by_user", "failed": "error"}
    async with await owner_session(owner) as db, db.begin():
        run = await db.get(Run, UUID(run_id))
        assert run is not None
        run.status = status
        run.end_reason = reasons[status]
        run.started_at = func.now()
        run.finished_at = func.now()


# ------------------------------------------------------------------ launch (CU-12)


async def test_launch_a_run(
    project: Project, run_queue: MemoryRunQueue, owner: AsyncEngine
) -> None:
    response = await project.launch()

    assert response.status_code == 202, response.text
    body = response.json()
    assert response.headers["Location"] == f"{project.runs}/{body['id']}"
    assert body["number"] == 1
    assert body["status"] == "queued"
    assert body["end_reason"] is None
    assert body["modules"] == ["configuration"]
    assert body["limits"] == {  # RF-47 defaults
        "requests_per_second": 5,
        "concurrency": 2,
        "max_requests": 5000,
        "max_duration_minutes": 30,
    }
    assert body["risk_confirmed"] is False
    assert body["contract_version"] is None  # Configuration does not need a contract
    assert body["progress"]["percent"] == 0
    assert body["progress"]["cells_planned"] == 0
    assert body["progress"]["findings_by_severity"]["total"] == 0
    assert body["created_resources"] == {"pending": 0, "deleted": 0, "failed": 0}
    assert body["started_at"] is None
    assert run_queue.enqueued == [UUID(body["id"])]
    async with await owner_session(owner) as db:
        run = await db.get(Run, UUID(body["id"]))
    assert run is not None
    assert run.job_id == f"run:{body['id']}"
    assert run.config["modules"] == ["configuration"]


async def test_modules_are_kept_in_catalog_order(ana: Analyst) -> None:
    project = await new_project(ana, contract=True)

    response = await project.launch(modules=["configuration", "authentication"])

    assert response.status_code == 202, response.text
    assert response.json()["modules"] == ["authentication", "configuration"]
    assert response.json()["contract_version"]["number"] == 1


async def test_limits_are_kept(project: Project) -> None:
    response = await project.launch(limits={"requests_per_second": 20, "max_duration_minutes": 1})

    assert response.json()["limits"] == {
        "requests_per_second": 20,
        "concurrency": 2,
        "max_requests": 5000,
        "max_duration_minutes": 1,
    }


@pytest.mark.parametrize(
    "body",
    [
        {"modules": []},
        {"modules": ["configuration", "configuration"]},
        {"modules": ["unknown"]},
        {"modules": ["configuration"], "limits": {"requests_per_second": 21}},
        {"modules": ["configuration"], "limits": {"concurrency": 6}},
        {"modules": ["configuration"], "limits": {"max_requests": 5001}},
        {"modules": ["configuration"], "limits": {"max_duration_minutes": 31}},
        {"modules": ["configuration"], "limits": {"timeout": 1}},
        {"modules": ["configuration"], "extra": True},
    ],
)
async def test_invalid_bodies(project: Project, body: dict[str, Any]) -> None:
    response = await project.analyst.request("POST", project.runs, json=body)

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "validation.failed"


async def test_one_active_run_per_project(project: Project, owner: AsyncEngine) -> None:
    first = await project.launch()

    second = await project.launch()

    assert second.status_code == 409
    assert second.json()["code"] == "project.active_run"
    await finish(owner, first.json()["id"])
    third = await project.launch()
    assert third.status_code == 202
    assert third.json()["number"] == 2


async def test_needs_a_verified_project(ana: Analyst) -> None:
    project = await new_project(ana, verified=False)

    response = await project.launch()

    assert response.status_code == 409
    assert response.json()["code"] == "project.not_verified"


async def test_editing_the_host_loses_the_verification(project: Project) -> None:
    edited = await project.analyst.request(
        "PATCH", f"/projects/{project.id}", json={"base_url": "https://otra.ejemplo.com"}
    )
    assert edited.status_code == 200

    response = await project.launch()

    assert response.json()["code"] == "project.not_verified"


async def test_unavailable_modules_are_named(project: Project) -> None:
    response = await project.launch(modules=["configuration", "authentication", "object_access"])

    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "run.module_unavailable"
    assert [e["field"] for e in body["errors"]] == ["modules.1", "modules.2"]  # no contract


async def test_medium_and_high_risk_need_a_confirmation(ana: Analyst) -> None:
    project = await new_project(ana, contract=True)

    refused = await project.launch(modules=["sql_injection"])
    accepted = await project.launch(modules=["sql_injection"], confirm_risk=True)

    assert refused.status_code == 422
    assert refused.json()["code"] == "run.risk_not_confirmed"
    assert refused.json()["errors"][0]["field"] == "confirm_risk"
    assert accepted.status_code == 202
    assert accepted.json()["risk_confirmed"] is True


async def test_a_confirmation_without_risky_modules_is_ignored(project: Project) -> None:
    response = await project.launch(confirm_risk=True)

    assert response.json()["risk_confirmed"] is False


@pytest.mark.parametrize("run_queue", [FailingRunQueue()])
async def test_without_the_queue_nothing_is_created(
    project: Project, run_queue: RunQueue, owner: AsyncEngine
) -> None:
    response = await project.launch()

    assert response.status_code == 503
    assert response.json()["code"] == "service.unavailable"
    async with await owner_session(owner) as db:
        count = await db.scalar(
            select(func.count()).select_from(Run).where(Run.project_id == UUID(project.id))
        )
    assert count == 0  # the project is not blocked by a run without a job (RN-07)


async def test_another_analysts_project_is_not_found(project: Project, new_analyst: Any) -> None:
    other: Analyst = new_analyst()
    await other.accept_terms()

    response = await other.request("POST", project.runs, json={"modules": ["configuration"]})

    assert response.status_code == 404


# ------------------------------------------------------------------ queries (RF-63)


async def test_get_a_run(project: Project) -> None:
    created = (await project.launch()).json()

    response = await project.analyst.request("GET", f"{project.runs}/{created['id']}")

    assert response.status_code == 200
    assert response.json() == created


async def test_a_finished_run_is_at_one_hundred_percent(
    project: Project, owner: AsyncEngine
) -> None:
    created = (await project.launch()).json()
    await finish(owner, created["id"])

    body = (await project.analyst.request("GET", f"{project.runs}/{created['id']}")).json()

    assert body["status"] == "completed"
    assert body["end_reason"] == "normal"
    assert body["progress"]["percent"] == 100
    assert body["progress"]["updated_at"] == body["finished_at"]


async def test_runs_of_other_projects_or_analysts_are_not_found(
    project: Project, ana: Analyst, new_analyst: Any
) -> None:
    created = (await project.launch()).json()
    sibling = await new_project(ana)
    other: Analyst = new_analyst()
    await other.accept_terms()

    from_sibling = await ana.request("GET", f"{sibling.runs}/{created['id']}")
    from_other = await other.request("GET", f"{project.runs}/{created['id']}")
    missing = await ana.request("GET", f"{project.runs}/{uuid.uuid4()}")

    assert from_sibling.status_code == from_other.status_code == missing.status_code == 404
    assert (await other.request("GET", project.runs)).status_code == 404


async def test_list_runs_most_recent_first(project: Project, owner: AsyncEngine) -> None:
    first = (await project.launch()).json()
    await finish(owner, first["id"], "failed")
    second = (await project.launch()).json()

    body = (await project.analyst.request("GET", project.runs)).json()
    running = (await project.analyst.request("GET", f"{project.runs}?status=queued")).json()
    finished = (
        await project.analyst.request("GET", f"{project.runs}?status=failed&status=completed")
    ).json()

    assert [item["number"] for item in body["items"]] == [2, 1]
    assert body["total"] == 2
    assert body["items"][0] == {
        "id": second["id"],
        "number": 2,
        "status": "queued",
        "end_reason": None,
        "modules": ["configuration"],
        "requests_sent": 0,
        "findings_by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
        },
        "created_at": second["created_at"],
        "started_at": None,
        "finished_at": None,
    }
    assert [item["id"] for item in running["items"]] == [second["id"]]
    assert [item["end_reason"] for item in finished["items"]] == ["error"]


async def test_a_repeated_status_filter_is_rejected(project: Project) -> None:
    response = await project.analyst.request("GET", f"{project.runs}?status=queued&status=queued")

    assert response.status_code == 422


async def test_the_dashboard_shows_the_launched_run(project: Project) -> None:
    created = (await project.launch()).json()

    body = (await project.analyst.request("GET", f"/projects/{project.id}")).json()

    assert body["last_run"]["id"] == created["id"]
    assert body["last_run"]["status"] == "queued"
