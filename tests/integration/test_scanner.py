"""The scanner (ADR-012; CU-12 steps 6 to 10, RF-20, RF-47).

`execute` runs against PostgreSQL as `hindama_scanner`, with the same privileges as in production.
The last tests go through SAQ and a real Redis (`HINDAMA_TEST_REDIS_URL`, a database of its own:
the tests empty it).
"""

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from typing import Any
from uuid import UUID

import pytest
import structlog
from pydantic import SecretStr
from saq import Queue
from saq.queue.redis import RedisQueue
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from hindama.core.ownership import CheckResult, Outcome
from hindama.core.run_queue import SaqRunQueue
from hindama.db.session import create_session_factory
from hindama.models import Project as ProjectRow
from hindama.models import Run
from hindama.models.enums import VerificationMethod
from hindama.scanner import execution
from hindama.scanner.config import ScannerSettings
from hindama.scanner.execution import Scanner, execute
from hindama.scanner.worker import build_worker
from tests.integration.conftest import Analyst
from tests.integration.test_runs import Project, finish, new_project, owner_session
from tests.ownership import ScriptedChecker

SCANNER_URL = os.environ.get("HINDAMA_TEST_SCANNER_DATABASE_URL")
REDIS_URL = os.environ.get("HINDAMA_TEST_REDIS_URL")


@pytest.fixture(scope="module")
async def scanner_engine() -> AsyncIterator[AsyncEngine]:
    if not SCANNER_URL:
        pytest.skip("HINDAMA_TEST_SCANNER_DATABASE_URL is not set")
    engine = create_async_engine(SCANNER_URL)
    yield engine
    await engine.dispose()


@pytest.fixture
def checker() -> ScriptedChecker:
    """The re-check of RF-20: DNS verifies unless a test says otherwise."""
    return ScriptedChecker()


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, checker: ScriptedChecker) -> Scanner:
    return Scanner(
        session_factory=create_session_factory(scanner_engine), ownership_checker=checker
    )


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
    assert run.cells_planned == 0  # no modules until task 3.2
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
                    "limits": {"max_duration_minutes": 30},
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
        database_url=SecretStr(SCANNER_URL), redis_url=SecretStr(REDIS_URL), concurrency=2
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
