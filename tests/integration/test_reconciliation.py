"""Reconciliation of runs left behind (CU-23, RNF-18, RF-90, RN-07).

Runs are launched through the API (with the queue in memory) and then aged in the database, as a
dead scanner or a lost queue would leave them. The reconciliation runs as `hindama_scanner`.
The last test kills a scan of the lab halfway and lets a new worker find it.
"""

import asyncio
import datetime as dt
import uuid
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from saq import Queue
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.core.run_events import RunEvent
from hindama.core.run_queue import job_key
from hindama.db.session import create_session_factory
from hindama.models import AuditLogEntry, Result, Run
from hindama.scanner import reconciliation
from hindama.scanner.config import ScannerSettings
from hindama.scanner.execution import Scanner, execute
from hindama.scanner.reconciliation import Reconciliation, purge_audit_log, reconcile
from hindama.scanner.worker import build_worker
from tests.conftest import TEST_AUDIT_KEY, TEST_CREDENTIAL_KEY
from tests.events import MemoryRunEvents
from tests.integration.conftest import SCANNER_URL, Analyst
from tests.integration.test_runs import Project, new_project, owner_session, start
from tests.integration.test_scanner import REDIS_URL, Touches, saq_queue, stored, until
from tests.lab.scanning import lab_project, lab_scanner
from tests.ownership import ScriptedChecker
from tests.queue import FailingRunQueue, MemoryRunQueue
from tests.servers import LocalServer

__all__ = ["saq_queue"]  # the fixture, shared with test_scanner.py


@pytest.fixture
async def project(ana: Analyst) -> Project:
    return await new_project(ana)


async def launch(project: Project) -> UUID:
    response = await project.launch()
    assert response.status_code == 202, response.text
    return UUID(response.json()["id"])


async def age(owner: AsyncEngine, run_id: UUID, **seconds_ago: int) -> None:
    """Moves timestamps of the run into the past, by the database clock."""
    values = {column: func.now() - dt.timedelta(seconds=s) for column, s in seconds_ago.items()}
    async with await owner_session(owner) as db, db.begin():
        await db.execute(update(Run).where(Run.id == run_id).values(**values))


async def run_reconciliation(
    scanner_engine: AsyncEngine, queue: Any, events: MemoryRunEvents
) -> Reconciliation:
    return await reconcile(create_session_factory(scanner_engine), queue, events)


# ------------------------------------------------------------------ running, heartbeat expired


async def test_a_running_run_without_heartbeat_fails(
    project: Project,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    run_id = await launch(project)
    await start(owner, run_id=str(run_id))
    async with await owner_session(owner) as db, db.begin():
        await db.execute(
            update(Run).where(Run.id == run_id).values(cells_planned=5, cells_evaluated=3)
        )
    await age(owner, run_id, heartbeat_at=61)

    result = await run_reconciliation(scanner_engine, run_queue, run_events)

    assert result.expired == [run_id]
    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("failed", "heartbeat_expired")  # RNF-18
    assert run.finished_at is not None
    assert run.cells_evaluated == 3  # the partial progress stays
    assert run_queue.aborted == [run_id]  # a scanner still holding it must stop writing
    assert run_events.of(run_id) == [RunEvent.END]
    # The project is free again (RN-07), and the API shows why the run ended.
    assert (await project.launch()).status_code == 202
    body = (await project.analyst.request("GET", f"{project.runs}/{run_id}")).json()
    assert (body["status"], body["end_reason"]) == ("failed", "heartbeat_expired")


async def test_a_running_run_that_beats_is_left_alone(
    project: Project,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    run_id = await launch(project)
    await start(owner, run_id=str(run_id))
    await age(owner, run_id, started_at=3600, heartbeat_at=50)  # long run, recent beat

    result = await run_reconciliation(scanner_engine, run_queue, run_events)

    assert run_id not in result.expired
    assert (await stored(owner, run_id)).status == "running"
    assert run_events.of(run_id) == []


async def test_a_run_being_claimed_is_left_for_the_next_pass(
    project: Project,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    run_id = await launch(project)
    await start(owner, run_id=str(run_id))
    await age(owner, run_id, heartbeat_at=120)

    async with await owner_session(owner) as db, db.begin():
        await db.scalar(select(Run).where(Run.id == run_id).with_for_update())  # a scanner holds it
        result = await asyncio.wait_for(
            run_reconciliation(scanner_engine, run_queue, run_events), timeout=5
        )

    assert run_id not in result.expired  # SKIP LOCKED: no waiting, no double handling
    assert (await stored(owner, run_id)).status == "running"


async def test_two_reconciliations_at_once_fail_each_run_once(
    ana: Analyst,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    run_ids = []
    for _ in range(4):
        run_id = await launch(await new_project(ana))
        await start(owner, run_id=str(run_id))
        await age(owner, run_id, heartbeat_at=120)
        run_ids.append(run_id)

    first, second = await asyncio.gather(
        run_reconciliation(scanner_engine, run_queue, run_events),
        run_reconciliation(scanner_engine, run_queue, run_events),
    )

    mine = set(run_ids)
    assert mine <= set(first.expired) | set(second.expired)  # all reconciled
    assert not set(first.expired) & set(second.expired)  # none twice
    assert [event for run_id in run_ids for event in run_events.of(run_id)] == [RunEvent.END] * 4


# ------------------------------------------------------------------ queued, job lost


async def test_a_queued_run_with_its_job_is_left_alone(
    project: Project,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    run_id = await launch(project)
    await age(owner, run_id, created_at=3600)  # waiting long, but the queue still has it

    result = await run_reconciliation(scanner_engine, run_queue, run_events)

    assert run_id not in result.requeued + result.lost
    assert (await stored(owner, run_id)).status == "queued"
    assert run_queue.enqueued == [run_id]


async def test_a_recent_queued_run_without_job_is_enqueued_again(
    project: Project,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    run_id = await launch(project)
    await age(owner, run_id, created_at=9 * 60)
    run_queue.lost.add(run_id)  # Redis lost the queue

    result = await run_reconciliation(scanner_engine, run_queue, run_events)

    assert result.requeued == [run_id]
    run = await stored(owner, run_id)
    assert run.status == "queued"
    assert run.job_id == job_key(run_id)
    assert run_queue.enqueued == [run_id, run_id]
    assert run_events.of(run_id) == []


async def test_an_old_queued_run_without_job_fails(
    project: Project,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    run_id = await launch(project)
    await age(owner, run_id, created_at=11 * 60)
    run_queue.lost.add(run_id)

    result = await run_reconciliation(scanner_engine, run_queue, run_events)

    assert result.lost == [run_id]
    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("failed", "lost_in_queue")
    assert run.finished_at is not None
    assert run_events.of(run_id) == [RunEvent.END]
    assert (await project.launch()).status_code == 202  # RN-07


async def test_without_redis_only_the_expired_runs_are_reconciled(
    ana: Analyst,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    running = await launch(await new_project(ana))
    await start(owner, run_id=str(running))
    await age(owner, running, heartbeat_at=120)
    queued = await launch(await new_project(ana))
    await age(owner, queued, created_at=11 * 60)

    result = await run_reconciliation(scanner_engine, FailingRunQueue(), run_events)

    # The database alone proves a run is dead; only Redis can say a job is lost.
    assert result.expired == [running]
    assert (await stored(owner, running)).status == "failed"
    assert (await stored(owner, queued)).status == "queued"


# ------------------------------------------------------------------ audit log (RF-90)


async def test_the_scanner_purges_the_expired_audit_log(
    owner: AsyncEngine, scanner_engine: AsyncEngine
) -> None:
    marker = uuid.uuid4()  # its project_id: the action must belong to the catalog
    async with owner.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO audit_log (action, project_id, occurred_at)"
                " VALUES ('account_created', :a, now() - interval '7 months')"
            ),
            {"a": marker},
        )

    deleted = await purge_audit_log(create_session_factory(scanner_engine))

    assert deleted >= 1
    async with AsyncSession(owner) as db:
        left = await db.scalar(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.project_id == marker)
        )
    assert left == 0


# ------------------------------------------------------------------ a scanner dies (RNF-18)


async def test_a_new_worker_fails_the_run_a_dead_scanner_left(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    app: FastAPI,
    saq_queue: Queue,
    scanner_engine: AsyncEngine,
    owner: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert SCANNER_URL and REDIS_URL
    scanner: Scanner = lab_scanner(
        scanner_engine, app.state.credential_cipher, ScriptedChecker(), app.state.run_events
    )
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    run_id = await project.launch(["object_access"], requests_per_second=1, concurrency=1)

    # The scanner dies halfway: its task is cancelled with no request from the analyst.
    dying = asyncio.create_task(execute(scanner, run_id, Touches()))
    await until(owner, run_id, lambda run: run.cells_evaluated >= 1, seconds=20)
    dying.cancel()
    with pytest.raises(asyncio.CancelledError):
        await dying
    assert (await stored(owner, run_id)).status == "running"  # nobody ended it

    monkeypatch.setattr(reconciliation, "HEARTBEAT_EXPIRY_SECONDS", 1)
    await asyncio.sleep(1.5)
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
        await until(owner, run_id, lambda run: run.status != "running", seconds=10)
    finally:
        await worker.stop()
        await running

    run = await stored(owner, run_id)
    assert (run.status, run.end_reason) == ("failed", "heartbeat_expired")
    assert run.cells_evaluated >= 1
    async with await owner_session(owner) as db:
        results = await db.scalar(
            select(func.count()).select_from(Result).where(Result.run_id == run_id)
        )
    assert results == run.cells_evaluated  # the partial results stay (RNF-18)
