"""`/projects/{project_id}/runs` (CU-12 to CU-14; RF-44 to RF-47, RF-51, RF-52, RF-63, RN-01,
RN-05, RN-07).

The queue and the progress events are in memory here; the scanner tests (test_scanner.py) use Redis
and cancel a run while it scans the lab.
"""

import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.core.run_events import RunEvent
from hindama.core.run_queue import RunQueue
from hindama.models import DailyMetric, Run
from hindama.models.enums import DailyMetricName, Module
from hindama.services import projects as projects_service
from tests.events import MemoryRunEvents
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


async def start(owner: AsyncEngine, run_id: str) -> None:
    """As the scanner does when it takes the job."""
    async with await owner_session(owner) as db, db.begin():
        run = await db.get(Run, UUID(run_id))
        assert run is not None
        run.status = "running"
        run.started_at = func.now()
        run.heartbeat_at = func.now()


async def daily(owner: AsyncEngine, metric: DailyMetricName) -> int:
    """Today's value of an anonymous metric (RF-78)."""
    async with owner.connect() as connection:
        value = await connection.scalar(
            select(DailyMetric.value).where(
                DailyMetric.date == datetime.now(UTC).date(), DailyMetric.metric == metric
            )
        )
    return value or 0


def sse_events(body: str) -> list[tuple[str, dict[str, Any]]]:
    """`(event, data)` of a stream, without `retry` and pings."""
    result = []
    for block in body.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "event" in fields:
            result.append((fields["event"], json.loads(fields["data"])))
    return result


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


async def test_launching_and_repeating_count_as_started_runs(
    project: Project, owner: AsyncEngine
) -> None:
    before = await daily(owner, DailyMetricName.RUNS_STARTED)

    refused = await project.launch(modules=["authentication"])  # no contract: not counted
    created = (await project.launch()).json()
    await finish(owner, created["id"])
    repeated = await rerun(project, created["id"])

    assert repeated.status_code == 202, repeated.text
    assert refused.status_code == 422
    assert await daily(owner, DailyMetricName.RUNS_STARTED) == before + 2


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


@pytest.fixture
def every_module_implemented(monkeypatch: pytest.MonkeyPatch) -> None:
    """The risky modules are not in the scanner yet (`not_implemented`): RN-05 is still enforced."""
    monkeypatch.setattr(projects_service, "IMPLEMENTED_MODULES", frozenset(Module))


async def test_a_module_the_scanner_does_not_have_is_refused(ana: Analyst) -> None:
    project = await new_project(ana, contract=True)

    response = await project.launch(modules=["sql_injection"], confirm_risk=True)

    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "run.module_unavailable"  # RF-45: not dropped in silence
    assert [e["field"] for e in body["errors"]] == ["modules.0"]


@pytest.mark.usefixtures("every_module_implemented")
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


@pytest.mark.parametrize("run_queue", [FailingRunQueue()])
async def test_a_run_rolled_back_is_not_counted(
    project: Project, run_queue: RunQueue, owner: AsyncEngine
) -> None:
    before = await daily(owner, DailyMetricName.RUNS_STARTED)

    assert (await project.launch()).status_code == 503

    assert await daily(owner, DailyMetricName.RUNS_STARTED) == before


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


# ------------------------------------------------------------------ cancel (CU-14, RF-52)


async def test_a_queued_run_is_cancelled_at_once(
    project: Project, run_queue: MemoryRunQueue, run_events: MemoryRunEvents
) -> None:
    created = (await project.launch()).json()

    response = await project.analyst.request("POST", f"{project.runs}/{created['id']}/cancel")

    assert response.status_code == 202, response.text
    body = response.json()
    assert (body["status"], body["end_reason"]) == ("cancelled", "cancelled_by_user")
    assert body["cancel_requested_at"] is not None
    assert body["finished_at"] is not None
    assert body["progress"]["status"] == "cancelled"
    assert run_queue.aborted == [UUID(created["id"])]
    assert run_events.of(UUID(created["id"])) == [RunEvent.END]  # its streams close
    # The project is free for another run (RN-07).
    assert (await project.launch()).status_code == 202


async def test_cancelling_a_queued_run_counts_it_once(project: Project, owner: AsyncEngine) -> None:
    before = await daily(owner, DailyMetricName.RUNS_CANCELLED)
    created = (await project.launch()).json()
    cancel = f"{project.runs}/{created['id']}/cancel"

    await project.analyst.request("POST", cancel)
    again = await project.analyst.request("POST", cancel)

    assert again.status_code == 409  # already final: `run.not_active`
    assert await daily(owner, DailyMetricName.RUNS_CANCELLED) == before + 1


async def test_a_running_run_gets_the_request_and_its_job_is_aborted(
    project: Project, run_queue: MemoryRunQueue, run_events: MemoryRunEvents, owner: AsyncEngine
) -> None:
    created = (await project.launch()).json()
    await start(owner, created["id"])
    path = f"{project.runs}/{created['id']}/cancel"

    first = await project.analyst.request("POST", path)
    again = await project.analyst.request("POST", path)

    assert first.status_code == again.status_code == 202
    body = first.json()
    assert (body["status"], body["end_reason"]) == ("running", None)  # the scanner ends it
    assert body["cancel_requested_at"] is not None
    # Repeating it while the run stops answers the same (contract).
    assert again.json()["cancel_requested_at"] == body["cancel_requested_at"]
    assert run_queue.aborted == [UUID(created["id"])] * 2
    assert run_events.of(UUID(created["id"])) == []  # `end` comes from the scanner


@pytest.mark.parametrize("status", ["completed", "cancelled", "failed"])
async def test_a_finished_run_cannot_be_cancelled(
    project: Project, owner: AsyncEngine, run_queue: MemoryRunQueue, status: str
) -> None:
    created = (await project.launch()).json()
    await finish(owner, created["id"], status)

    response = await project.analyst.request("POST", f"{project.runs}/{created['id']}/cancel")

    assert response.status_code == 409
    assert response.json()["code"] == "run.not_active"  # CU-14 E1
    assert run_queue.aborted == []


async def test_cancelling_another_analysts_run_is_not_found(
    project: Project, new_analyst: Any, run_queue: MemoryRunQueue, owner: AsyncEngine
) -> None:
    created = (await project.launch()).json()
    other: Analyst = new_analyst()
    await other.accept_terms()

    response = await other.request("POST", f"{project.runs}/{created['id']}/cancel")
    missing = await project.analyst.request("POST", f"{project.runs}/{uuid.uuid4()}/cancel")

    assert response.status_code == missing.status_code == 404  # RN-02: not 403
    assert run_queue.aborted == []
    async with await owner_session(owner) as db:
        run = await db.get(Run, UUID(created["id"]))
    assert run is not None
    assert (run.status, run.cancel_requested_at) == ("queued", None)


@pytest.fixture
def failing_queue() -> MemoryRunQueue:
    """Accepts the launch; Redis goes down before the cancellation."""
    queue = MemoryRunQueue()

    async def down(run_id: UUID) -> None:
        await FailingRunQueue().abort(run_id)

    queue.abort = down  # type: ignore[method-assign]
    return queue


async def test_without_the_queue_a_running_run_is_not_cancelled(
    ana: Analyst, owner: AsyncEngine, app: Any, failing_queue: MemoryRunQueue
) -> None:
    app.state.run_queue = failing_queue
    project = await new_project(ana)
    created = (await project.launch()).json()
    await start(owner, created["id"])

    response = await project.analyst.request("POST", f"{project.runs}/{created['id']}/cancel")

    assert response.status_code == 503  # nothing would stop the scanner
    async with await owner_session(owner) as db:
        run = await db.get(Run, UUID(created["id"]))
    assert run is not None
    assert (run.status, run.cancel_requested_at) == ("running", None)  # rolled back


async def test_without_the_queue_a_queued_run_is_still_cancelled(
    ana: Analyst, app: Any, failing_queue: MemoryRunQueue
) -> None:
    app.state.run_queue = failing_queue
    project = await new_project(ana)
    created = (await project.launch()).json()

    response = await project.analyst.request("POST", f"{project.runs}/{created['id']}/cancel")

    assert response.status_code == 202  # the scanner skips a job whose run is not queued
    assert response.json()["status"] == "cancelled"


# ------------------------------------------------------------------ progress (CU-13, RF-51)


async def test_the_stream_of_a_finished_run_is_snapshot_and_end(
    project: Project, owner: AsyncEngine
) -> None:
    created = (await project.launch()).json()
    await finish(owner, created["id"])

    response = await project.analyst.request("GET", f"{project.runs}/{created['id']}/events")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    assert response.text.startswith("retry: 3000\n\nid: 1\nevent: snapshot\n")
    run = (await project.analyst.request("GET", f"{project.runs}/{created['id']}")).json()
    assert sse_events(response.text) == [("snapshot", run), ("end", run)]


async def test_reconnecting_starts_again_with_a_snapshot(
    project: Project, owner: AsyncEngine
) -> None:
    created = (await project.launch()).json()
    await finish(owner, created["id"])

    analyst = project.analyst
    response = await analyst.client.get(
        f"{project.runs}/{created['id']}/events",
        headers={**analyst.headers, "Last-Event-ID": "41"},
    )

    assert response.text.startswith("retry: 3000\n\nid: 42\nevent: snapshot\n")  # CU-13 A1


async def test_the_stream_ends_when_a_queued_run_is_cancelled(
    project: Project, run_events: MemoryRunEvents
) -> None:
    created = (await project.launch()).json()
    path = f"{project.runs}/{created['id']}"
    streaming = asyncio.create_task(project.analyst.request("GET", f"{path}/events"))
    await asyncio.wait_for(run_events.subscribed.wait(), timeout=5)

    cancelled = await project.analyst.request("POST", f"{path}/cancel")
    response = await asyncio.wait_for(streaming, timeout=5)

    assert cancelled.status_code == 202
    events = sse_events(response.text)
    assert [name for name, _ in events] == ["snapshot", "end"]
    # The snapshot is the database when the stream read it: the cancellation may be committed
    # by then. Either way the stream ends with the cancelled run.
    assert events[0][1]["status"] in ("queued", "cancelled")
    assert events[1][1] == cancelled.json()
    assert run_events.listening(UUID(created["id"])) == 0


async def test_the_stream_of_another_analysts_run_is_not_found(
    project: Project, new_analyst: Any, run_events: MemoryRunEvents
) -> None:
    created = (await project.launch()).json()
    other: Analyst = new_analyst()
    await other.accept_terms()

    response = await other.request("GET", f"{project.runs}/{created['id']}/events")

    assert response.status_code == 404  # RN-02
    assert response.headers["content-type"] == "application/problem+json"
    assert run_events.subscribers == {}  # it never subscribed


# ------------------------------------------------------------------ rerun (CU-17, RF-71)


async def rerun(project: Project, run_id: str, **body: Any) -> Any:
    return await project.analyst.request("POST", f"{project.runs}/{run_id}/rerun", json=body)


async def test_rerun_copies_the_configuration(
    ana: Analyst, owner: AsyncEngine, run_queue: MemoryRunQueue
) -> None:
    project = await new_project(ana, contract=True)
    limits = {
        "requests_per_second": 7,
        "concurrency": 1,
        "max_requests": 10,
        "max_duration_minutes": 2,
    }
    original = (
        await project.launch(modules=["configuration", "authentication"], limits=limits)
    ).json()
    await finish(owner, original["id"])

    response = await rerun(project, original["id"])

    assert response.status_code == 202, response.text
    body = response.json()
    assert response.headers["Location"] == f"{project.runs}/{body['id']}"
    assert body["number"] == 2
    assert body["status"] == "queued"
    assert body["source_run_id"] == original["id"]
    assert body["modules"] == original["modules"] == ["authentication", "configuration"]
    assert body["limits"] == original["limits"] == limits
    assert body["contract_version"] == original["contract_version"]
    assert run_queue.enqueued[-1] == UUID(body["id"])
    fetched = await project.analyst.request("GET", f"{project.runs}/{body['id']}")
    assert fetched.json() == body
    assert original["source_run_id"] is None


async def test_any_finished_run_can_be_repeated(project: Project, owner: AsyncEngine) -> None:
    first = (await project.launch(limits={"concurrency": 1})).json()
    await finish(owner, first["id"], "failed")
    second = (await project.launch()).json()
    await finish(owner, second["id"], "cancelled")

    response = await rerun(project, first["id"])

    assert response.status_code == 202, response.text
    assert response.json()["source_run_id"] == first["id"]
    assert response.json()["limits"]["concurrency"] == 1


async def test_rerunning_an_active_run_is_the_projects_active_run(project: Project) -> None:
    created = (await project.launch()).json()

    response = await rerun(project, created["id"])

    assert response.status_code == 409
    assert response.json()["code"] == "project.active_run"  # RN-07


async def test_rerun_needs_a_verified_project(project: Project, owner: AsyncEngine) -> None:
    created = (await project.launch()).json()
    await finish(owner, created["id"])
    edited = await project.analyst.request(
        "PATCH", f"/projects/{project.id}", json={"base_url": "https://otra.ejemplo.com"}
    )
    assert edited.status_code == 200

    response = await rerun(project, created["id"])

    assert response.status_code == 409
    assert response.json()["code"] == "project.not_verified"  # RN-01


@pytest.mark.usefixtures("every_module_implemented")
async def test_rerun_asks_for_the_risk_confirmation_again(ana: Analyst, owner: AsyncEngine) -> None:
    project = await new_project(ana, contract=True)
    original = (await project.launch(modules=["sql_injection"], confirm_risk=True)).json()
    await finish(owner, original["id"])

    refused = await rerun(project, original["id"])
    accepted = await rerun(project, original["id"], confirm_risk=True)

    assert refused.status_code == 422
    assert refused.json()["code"] == "run.risk_not_confirmed"  # RF-46: in every run
    assert refused.json()["errors"][0]["field"] == "confirm_risk"
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["risk_confirmed"] is True


async def test_a_module_no_longer_available_is_not_dropped(
    project: Project, owner: AsyncEngine
) -> None:
    created = (await project.launch()).json()
    await finish(owner, created["id"])
    async with await owner_session(owner) as db, db.begin():  # as if its requirements were lost
        run = await db.get(Run, UUID(created["id"]))
        assert run is not None
        run.config = {**run.config, "modules": ["authentication", "configuration"]}

    response = await rerun(project, created["id"])

    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "run.module_unavailable"
    assert [e["field"] for e in body["errors"]] == ["modules.0"]  # authentication: no contract


@pytest.mark.parametrize("body", [{"extra": True}, {"confirm_risk": "maybe"}])
async def test_invalid_rerun_bodies(project: Project, owner: AsyncEngine, body: Any) -> None:
    created = (await project.launch()).json()
    await finish(owner, created["id"])

    response = await rerun(project, created["id"], **body)

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "validation.failed"


async def test_rerunning_another_analysts_or_projects_run_is_not_found(
    project: Project, ana: Analyst, new_analyst: Any, owner: AsyncEngine, run_queue: MemoryRunQueue
) -> None:
    created = (await project.launch()).json()
    await finish(owner, created["id"])
    enqueued = len(run_queue.enqueued)
    other: Analyst = new_analyst()
    await other.accept_terms()
    others_project = await new_project(other)
    sibling = await new_project(ana)

    foreign = await other.request("POST", f"{project.runs}/{created['id']}/rerun", json={})
    crossed = await other.request("POST", f"{others_project.runs}/{created['id']}/rerun", json={})
    wrong_project = await rerun(sibling, created["id"])
    missing = await rerun(project, str(uuid.uuid4()))

    statuses = {r.status_code for r in (foreign, crossed, wrong_project, missing)}
    assert statuses == {404}  # RN-02: not 403
    assert len(run_queue.enqueued) == enqueued
