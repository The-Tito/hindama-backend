"""The scanner (ADR-012; CU-12 steps 6 to 10, RF-20, RF-47).

`execute` runs against PostgreSQL as `hindama_scanner`, with the same privileges as in production.
The last tests go through SAQ and a real Redis (`HINDAMA_TEST_REDIS_URL`, a database of its own:
the tests empty it).
"""

import asyncio
import contextlib
import dataclasses
import os
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any
from uuid import UUID

import pytest
import structlog
from fastapi import FastAPI
from pydantic import SecretStr
from saq import Queue
from saq.queue.redis import RedisQueue
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.core.ownership import CheckResult, Outcome
from hindama.core.run_events import RedisRunEvents, RunEvent, Subscription
from hindama.core.run_queue import SaqRunQueue
from hindama.core.safe_http import SafeHttpClient
from hindama.models import Project as ProjectRow
from hindama.models import Result, Run
from hindama.models.enums import VerificationMethod
from hindama.scanner import execution
from hindama.scanner.config import ScannerSettings
from hindama.scanner.execution import Scanner, execute
from hindama.scanner.requester import SCAN_LIMITS
from hindama.scanner.worker import build_worker
from tests.audit import actions, audit_entries
from tests.conftest import TEST_AUDIT_KEY, TEST_CREDENTIAL_KEY, TEST_HASHER
from tests.events import MemoryRunEvents
from tests.integration.conftest import SCANNER_URL, Analyst
from tests.integration.test_runs import Project, finish, new_project, owner_session, sse_events
from tests.lab.scanning import lab_project, lab_scanner
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer, ScriptedResolver

REDIS_URL = os.environ.get("HINDAMA_TEST_REDIS_URL")


@pytest.fixture
def checker() -> ScriptedChecker:
    """The re-check of RF-20: DNS verifies unless a test says otherwise."""
    return ScriptedChecker()


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, checker: ScriptedChecker, app: FastAPI) -> Scanner:
    return lab_scanner(scanner_engine, app.state.credential_cipher, checker, app.state.run_events)


class Touches:
    def __init__(self) -> None:
        self.count = 0

    async def __call__(self) -> None:
        self.count += 1


@pytest.fixture
async def project(ana: Analyst) -> Project:
    return await new_project(ana)


async def launch(project: Project) -> UUID:
    response = await project.launch()
    assert response.status_code == 202, response.text
    return UUID(response.json()["id"])


async def stored(owner: AsyncEngine, run_id: UUID) -> Run:
    async with await owner_session(owner) as db:
        run = await db.get(Run, run_id)
    assert run is not None
    return run


async def until(
    owner: AsyncEngine, run_id: UUID, condition: Callable[[Run], bool], seconds: float
) -> None:
    async with asyncio.timeout(seconds):
        while True:
            if condition(await stored(owner, run_id)):
                return
            await asyncio.sleep(0.05)


async def verification_status(owner: AsyncEngine, project: Project) -> str:
    async with await owner_session(owner) as db:
        row = await db.get(ProjectRow, UUID(project.id))
    assert row is not None
    return row.verification_status


# ------------------------------------------------------------------ the life of a run


async def test_a_run_goes_from_queued_to_completed(
    project: Project, scanner: Scanner, checker: ScriptedChecker, owner: AsyncEngine
) -> None:
    run_id = await launch(project)

    await execute(scanner, run_id, Touches())

    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("completed", "normal")
    assert run.started_at is not None
    assert run.finished_at is not None
    assert run.started_at <= run.finished_at
    # Configuration plans one cell; nothing listens at the project's host here, so it is an error
    # cell, and the run still completes (test_configuration.py runs it against the lab).
    assert run.cells_planned == run.cells_evaluated == 1
    assert run.current_module is None
    assert [call[0] for call in checker.calls] == [VerificationMethod.DNS]  # RF-20


async def test_the_api_shows_the_finished_run(project: Project, scanner: Scanner) -> None:
    run_id = await launch(project)

    await execute(scanner, run_id, Touches())

    body = (await project.analyst.request("GET", f"{project.runs}/{run_id}")).json()
    assert body["status"] == "completed"
    assert body["progress"]["percent"] == 100


@pytest.mark.parametrize(
    "outcome",
    [
        Outcome.TXT_MISSING,
        Outcome.FILE_NOT_FOUND,
        Outcome.CONTENT_MISMATCH,
        Outcome.DESTINATION_NOT_ALLOWED,
    ],
)
async def test_a_lost_verification_cancels_the_run(
    project: Project,
    scanner: Scanner,
    checker: ScriptedChecker,
    owner: AsyncEngine,
    outcome: Outcome,
) -> None:
    run_id = await launch(project)
    checker.results[VerificationMethod.DNS] = CheckResult(outcome)

    await execute(scanner, run_id, Touches())

    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("cancelled", "verification_invalid")  # CU-12 E2
    assert await verification_status(owner, project) == "pending"
    # RF-81: audited with the change, on behalf of the owner, with the host's HMAC.
    (lost,) = [
        e
        for e in await audit_entries(owner, project_id=project.id)
        if e.action == "project_verification_lost"
    ]
    me = (await project.analyst.request("GET", "/me")).json()
    assert str(lost.user_id) == me["id"]
    assert lost.source_ip is None  # the scanner has no browser
    assert lost.details == {"run_id": str(run_id), "verification_method": "dns"}
    assert bytes(lost.host_hmac or b"") == TEST_HASHER.digest("api.ejemplo.com").value


async def test_blocked_destinations_of_a_run_are_audited_once(
    project: Project, scanner: Scanner, owner: AsyncEngine
) -> None:
    """RF-50, RF-81: the project's host now resolves to a private address. Every request is
    blocked; the log gets one entry per reason, not one per request."""

    def private_client(host: str) -> SafeHttpClient:
        return SafeHttpClient(host, resolver=ScriptedResolver(["10.0.0.9"]), limits=SCAN_LIMITS)

    run_id = await launch(project)

    await execute(dataclasses.replace(scanner, http_client=private_client), run_id, Touches())

    blocked = [
        e
        for e in await audit_entries(owner, project_id=project.id)
        if e.action == "destination_blocked"
    ]
    assert [e.details for e in blocked] == [
        {"stage": "run", "block_reason": "address_not_allowed", "run_id": str(run_id)}
    ]
    assert bytes(blocked[0].host_hmac or b"") == TEST_HASHER.digest("api.ejemplo.com").value


async def test_a_run_without_blocks_audits_nothing_from_the_scanner(
    project: Project, scanner: Scanner, owner: AsyncEngine
) -> None:
    run_id = await launch(project)

    await execute(scanner, run_id, Touches())

    assert set(actions(await audit_entries(owner, project_id=project.id))) == {
        "project_created",
        "project_verified",
        "run_launched",
    }


async def test_an_unreachable_host_fails_the_run_but_keeps_the_verification(
    project: Project, scanner: Scanner, checker: ScriptedChecker, owner: AsyncEngine
) -> None:
    run_id = await launch(project)
    checker.results[VerificationMethod.DNS] = CheckResult(Outcome.CONNECTION_ERROR)

    await execute(scanner, run_id, Touches())

    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("failed", "error")
    assert await verification_status(owner, project) == "verified"


async def test_a_run_that_is_not_queued_is_left_alone(
    project: Project, scanner: Scanner, checker: ScriptedChecker, owner: AsyncEngine
) -> None:
    run_id = await launch(project)
    await finish(owner, str(run_id), "cancelled")

    await execute(scanner, run_id, Touches())

    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("cancelled", "cancelled_by_user")
    assert checker.calls == []


async def test_a_run_that_never_appears_is_dropped(
    scanner: Scanner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(execution, "VISIBILITY_WAIT_SECONDS", 0.2)

    await execute(scanner, uuid.uuid4(), Touches())  # rolled back by the API: nothing to do


async def test_the_scanner_waits_for_the_api_to_commit(
    project: Project, scanner: Scanner, owner: AsyncEngine
) -> None:
    """The API enqueues before committing (services/runs.py): the job may arrive first."""
    run_id = uuid.uuid4()
    async with AsyncSession(owner, expire_on_commit=False) as db, db.begin():
        db.add(
            Run(
                id=run_id,
                project_id=UUID(project.id),
                number=1,
                config={
                    "modules": ["configuration"],
                    "limits": {  # as the API stores them: always complete
                        "requests_per_second": 5,
                        "concurrency": 2,
                        "max_requests": 5000,
                        "max_duration_minutes": 30,
                    },
                    "risk_confirmed": False,
                },
            )
        )
        await db.flush()
        task = asyncio.create_task(execute(scanner, run_id, Touches()))
        await asyncio.sleep(0.3)  # the scanner is already looking for the row
        assert not task.done()

    await asyncio.wait_for(task, timeout=5)
    run = await stored(owner, run_id)
    assert run.status == "completed"


async def test_the_duration_limit_ends_the_run(
    project: Project, scanner: Scanner, owner: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def endless(*_: Any) -> None:
        await asyncio.sleep(60)

    monkeypatch.setattr(execution, "_modules", endless)
    monkeypatch.setattr(execution, "SECONDS_PER_MINUTE", 0.05)  # 1 minute -> 50 ms
    response = await project.launch(limits={"max_duration_minutes": 1})
    run_id = UUID(response.json()["id"])

    await asyncio.wait_for(execute(scanner, run_id, Touches()), timeout=5)

    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("completed", "limit_reached")  # RF-47, CU-12 E5


async def test_the_heartbeat_touches_the_job_and_the_row(
    project: Project, scanner: Scanner, owner: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def slow(*_: Any) -> None:
        await asyncio.sleep(0.3)

    monkeypatch.setattr(execution, "_modules", slow)
    monkeypatch.setattr(execution, "HEARTBEAT_INTERVAL_SECONDS", 0.05)
    run_id = await launch(project)
    touches = Touches()

    await execute(scanner, run_id, touches)

    run = await stored(owner, run_id)
    assert touches.count >= 2
    assert run.heartbeat_at is not None
    assert run.started_at is not None
    assert run.heartbeat_at > run.started_at


async def test_a_failed_beat_does_not_stop_the_heartbeat(
    project: Project, scanner: Scanner, owner: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise a live run would stop beating and the reconciliation would fail it (CU-23)."""

    async def slow(*_: Any) -> None:
        await asyncio.sleep(0.4)

    class Flaky(Touches):
        async def __call__(self) -> None:
            await super().__call__()
            if self.count == 1:
                raise ConnectionError("redis://:secreto@redis:6379")

    monkeypatch.setattr(execution, "_modules", slow)
    monkeypatch.setattr(execution, "HEARTBEAT_INTERVAL_SECONDS", 0.05)
    run_id = await launch(project)
    touches = Flaky()

    with structlog.testing.capture_logs() as logs:
        monkeypatch.setattr(execution, "log", structlog.get_logger("test"))
        await execute(scanner, run_id, touches)

    assert touches.count >= 3  # it kept beating after the failure
    assert (await stored(owner, run_id)).status == "completed"
    failed = [entry for entry in logs if entry["event"] == "run_heartbeat_failed"]
    assert failed == [
        {
            "event": "run_heartbeat_failed",
            "log_level": "warning",
            "run_id": str(run_id),
            "error": "ConnectionError",
        }
    ]
    assert "secreto" not in repr(logs)


def test_the_worker_schedules_the_reconciliation_and_the_purge() -> None:
    settings = ScannerSettings(
        database_url=SecretStr("postgresql+asyncpg://unused@localhost:1/unused"),
        redis_url=SecretStr("redis://localhost:1/0"),
        credential_keys={1: SecretStr(TEST_CREDENTIAL_KEY)},
        audit_hmac_keys={1: SecretStr(TEST_AUDIT_KEY)},
    )

    worker = build_worker(settings)

    schedules = {job.function.__name__: job.cron for job in worker.cron_jobs}
    assert schedules == {"reconcile_runs": "*/5 * * * *", "purge_audit": "17 4 * * *"}  # CU-23
    assert all(job.unique for job in worker.cron_jobs)  # once per schedule, however many scanners


async def test_an_error_fails_only_that_run_and_logs_only_its_type(
    project: Project, scanner: Scanner, owner: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_: Any) -> None:
        raise RuntimeError("token=secreto-de-la-api")

    monkeypatch.setattr(execution, "_modules", broken)
    run_id = await launch(project)

    with structlog.testing.capture_logs() as logs:
        monkeypatch.setattr(execution, "log", structlog.get_logger("test"))
        await execute(scanner, run_id, Touches())

    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("failed", "error")
    errors = [entry for entry in logs if entry["event"] == "run_error"]
    assert errors == [
        {"event": "run_error", "log_level": "error", "run_id": str(run_id), "error": "RuntimeError"}
    ]
    assert "secreto" not in repr(logs)


# ------------------------------------------------------------------ progress (CU-13, RF-51)


class PacedRunEvents:
    """Gives the stream time to read each `progress`. Without it, a run faster than the stream
    goes from `snapshot` to `end`, which is right but leaves nothing to check in between."""

    def __init__(self, events: MemoryRunEvents) -> None:
        self.events = events

    async def publish(self, run_id: UUID, event: RunEvent) -> None:
        await self.events.publish(run_id, event)
        if event == RunEvent.PROGRESS:
            await asyncio.sleep(0.3)

    def subscribe(self, run_id: UUID) -> contextlib.AbstractAsyncContextManager[Subscription]:
        return self.events.subscribe(run_id)

    async def close(self) -> None:
        await self.events.close()


async def test_the_stream_follows_the_run_from_snapshot_to_end(
    project: Project, scanner: Scanner, run_events: MemoryRunEvents
) -> None:
    run_id = await launch(project)
    path = f"{project.runs}/{run_id}"
    streaming = asyncio.create_task(project.analyst.request("GET", f"{path}/events"))
    await asyncio.wait_for(run_events.subscribed.wait(), timeout=5)
    paced = dataclasses.replace(scanner, events=PacedRunEvents(run_events))

    await execute(paced, run_id, Touches())
    response = await asyncio.wait_for(streaming, timeout=5)

    events = sse_events(response.text)
    names = [name for name, _ in events]
    assert names[0] == "snapshot"
    assert set(names[1:-1]) == {"progress"}
    assert names[-1] == "end"
    # The snapshot is the database when the stream read it, right after subscribing: the scanner
    # may have claimed the run by then (seen in CI). Every `progress` comes after the claim.
    assert events[0][1]["status"] in ("queued", "running")
    assert events[1][1]["status"] == "running"
    final = (await project.analyst.request("GET", path)).json()
    assert events[-1][1] == final
    assert final["progress"]["percent"] == 100
    # The scanner published while it ran, and `end` last (ADR-006).
    assert run_events.of(run_id)[-1] == RunEvent.END
    assert RunEvent.PROGRESS in run_events.of(run_id)


async def test_a_cancelled_task_without_a_request_is_left_to_the_reconciliation(
    project: Project, scanner: Scanner, owner: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def endless(*_: Any) -> None:
        await asyncio.sleep(60)

    monkeypatch.setattr(execution, "_modules", endless)
    run_id = await launch(project)
    task = asyncio.create_task(execute(scanner, run_id, Touches()))
    await asyncio.sleep(0.2)

    task.cancel()  # the worker stopping, not the analyst (CU-23, task 3.4)
    with pytest.raises(asyncio.CancelledError):
        await task

    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("running", None)


# ------------------------------------------------------------------ through SAQ and Redis


@pytest.fixture
async def saq_queue() -> AsyncIterator[Queue]:
    if not REDIS_URL:
        pytest.skip("HINDAMA_TEST_REDIS_URL is not set")
    queue = Queue.from_url(REDIS_URL, name=f"runs-test-{uuid.uuid4().hex}")
    assert isinstance(queue, RedisQueue)
    yield queue
    await queue.redis.flushdb()  # a database only for the tests
    await queue.disconnect()


async def test_the_worker_executes_an_enqueued_run(
    project: Project, scanner: Scanner, saq_queue: Queue, owner: AsyncEngine
) -> None:
    assert SCANNER_URL and REDIS_URL
    run_id = await launch(project)
    key = await SaqRunQueue(saq_queue).enqueue(run_id)
    settings = ScannerSettings(
        database_url=SecretStr(SCANNER_URL),
        redis_url=SecretStr(REDIS_URL),
        concurrency=2,
        credential_keys={1: SecretStr(TEST_CREDENTIAL_KEY)},
        audit_hmac_keys={1: SecretStr(TEST_AUDIT_KEY)},
    )
    worker = build_worker(settings, queue=saq_queue, scanner=scanner)
    job = await saq_queue.job(key)
    assert job is not None
    running = asyncio.create_task(worker.start())
    try:
        # Wait for the job, not for the row: the scanner writes the final state just before the
        # job function returns, and stopping the worker in between aborts the job (seen in CI).
        await job.refresh(until_complete=10)
    finally:
        await worker.stop()
        await running
    assert key == f"run:{run_id}"
    assert job.status == "complete"
    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("completed", "normal")


async def test_enqueuing_the_same_run_twice_keeps_one_job(
    project: Project, saq_queue: Queue
) -> None:
    queue = SaqRunQueue(saq_queue)
    run_id = await launch(project)

    first = await queue.enqueue(run_id)
    second = await queue.enqueue(run_id)

    assert first == second == f"run:{run_id}"
    assert await saq_queue.count("queued") == 1


async def test_redis_carries_the_events_of_one_run() -> None:
    if not REDIS_URL:
        pytest.skip("HINDAMA_TEST_REDIS_URL is not set")
    events = RedisRunEvents.from_url(REDIS_URL)
    run_id, other = uuid.uuid4(), uuid.uuid4()
    try:
        async with events.subscribe(run_id) as subscription:
            await events.publish(other, RunEvent.END)
            await events.publish(run_id, RunEvent.PROGRESS)
            await events.publish(run_id, RunEvent.END)

            received = [await subscription.receive(1.0) for _ in range(2)]
            assert received == [RunEvent.PROGRESS, RunEvent.END]
            assert await subscription.receive(0.05) is None
    finally:
        await events.close()


async def test_cancelling_a_running_scan_stops_it_and_keeps_the_partial_results(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    app: FastAPI,
    saq_queue: Queue,
    scanner_engine: AsyncEngine,
    owner: AsyncEngine,
) -> None:
    """CU-14, RF-52, PT-02: SAQ, Redis and the lab, at one request per second."""
    assert SCANNER_URL and REDIS_URL
    events = RedisRunEvents.from_url(REDIS_URL)
    app.state.run_queue = SaqRunQueue(saq_queue)
    app.state.run_events = events
    scanner = lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker(), events)
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    run_id = await project.launch(["object_access"], requests_per_second=1, concurrency=1)
    path = f"/projects/{project.id}/runs/{run_id}"
    settings = ScannerSettings(
        database_url=SecretStr(SCANNER_URL),
        redis_url=SecretStr(REDIS_URL),
        concurrency=1,
        credential_keys={1: SecretStr(TEST_CREDENTIAL_KEY)},
        audit_hmac_keys={1: SecretStr(TEST_AUDIT_KEY)},
    )
    worker = build_worker(settings, queue=saq_queue, scanner=scanner)
    running = asyncio.create_task(worker.start())
    try:
        streaming = asyncio.create_task(ana.request("GET", f"{path}/events"))
        await until(owner, run_id, lambda run: run.cells_evaluated >= 1, seconds=20)

        loop = asyncio.get_running_loop()
        asked = loop.time()
        response = await ana.request("POST", f"{path}/cancel")
        assert response.status_code == 202, response.text
        await until(owner, run_id, lambda run: run.status != "running", seconds=10)
        stopped = loop.time() - asked
        stream = await asyncio.wait_for(streaming, timeout=5)
        job = await saq_queue.job(f"run:{run_id}")
    finally:
        await worker.stop()
        await running
        await events.close()

    assert stopped < 5  # RF-52
    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("cancelled", "cancelled_by_user")
    assert run.cancel_requested_at is not None
    assert 1 <= run.cells_evaluated < run.cells_planned
    async with await owner_session(owner) as db:
        results = await db.scalar(
            select(func.count()).select_from(Result).where(Result.run_id == run_id)
        )
    assert results == run.cells_evaluated  # the partial results stay
    assert job is not None
    assert job.status == "aborted"
    names = [name for name, _ in sse_events(stream.text)]
    assert names[0] == "snapshot"
    assert names[-1] == "end"
    assert sse_events(stream.text)[-1][1]["status"] == "cancelled"
