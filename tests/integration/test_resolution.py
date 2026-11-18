"""Resolving the findings a run evaluated again and no longer found (RF-68, RF-69, RF-73, RF-78;
ADR-014; modelo.md sections 6 and 7.3).

Three levels: the rule case by case (called as the scanner calls it), the reconciliation of a run
that stopped beating, and the scanner against the lab before and after the analyst fixes it.
"""

import datetime as dt
import json
from collections.abc import Iterator
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi import FastAPI
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.db.session import create_session_factory
from hindama.models import Finding, FindingEvent, FindingMetric, Run
from hindama.models.enums import EndReason, RunStatus
from hindama.scanner import execution
from hindama.scanner.execution import Scanner
from hindama.scanner.reconciliation import reconcile
from hindama.scanner.resolution import resolve_not_detected
from tests.events import MemoryRunEvents
from tests.integration.conftest import Analyst
from tests.integration.test_findings import Seeded, add_finding, finish
from tests.integration.test_run_results import CONTRACT, Matrix, add_cells, new_matrix
from tests.integration.test_runs import owner_session, start
from tests.lab.app import Mode, build_lab
from tests.lab.scanning import lab_project, lab_scanner, run_lab
from tests.ownership import ScriptedChecker
from tests.queue import MemoryRunQueue
from tests.servers import LocalServer

ORDERS, USERS, NEW_ORDER = ("GET", "/orders"), ("GET", "/users"), ("POST", "/orders")


class TwoRuns:
    """A finished first run that detected the findings, and a second one being evaluated."""

    def __init__(self, seeded: Seeded, second: Matrix) -> None:
        self.seeded = seeded
        self.second = second

    @property
    def project_id(self) -> UUID:
        return UUID(self.seeded.project.id)

    @property
    def run_id(self) -> UUID:
        return UUID(self.second.run_id)

    def finding(self, label: str) -> UUID:
        return UUID(self.seeded.findings[label])


async def two_runs(ana: Analyst, owner: AsyncEngine) -> TwoRuns:
    first = await new_matrix(ana, owner)
    seeded = Seeded(first)
    await finish(owner, first.run_id)
    launched = (await first.project.launch()).json()
    second = Matrix(first.project, launched["id"])
    second.operations, second.identities = first.operations, first.identities
    seeded.runs.append(launched["id"])
    await start(owner, launched["id"])
    return TwoRuns(seeded, second)


async def states(owner: AsyncEngine, runs: TwoRuns) -> dict[str, tuple[str, str | None]]:
    async with AsyncSession(owner) as db:
        rows = await db.execute(
            select(Finding.id, Finding.status, Finding.resolution_reason).where(
                Finding.project_id == runs.project_id
            )
        )
        by_id = {finding_id: (status, reason) for finding_id, status, reason in rows}
    return {label: by_id[UUID(value)] for label, value in runs.seeded.findings.items()}


async def resolve(scanner_engine: AsyncEngine, runs: TwoRuns) -> int:
    """As `_finish` does it: with the scanner's role, in one transaction."""
    async with AsyncSession(scanner_engine) as db, db.begin():
        return await resolve_not_detected(db, runs.project_id, runs.run_id)


@pytest.fixture
async def runs(ana: Analyst, owner: AsyncEngine) -> TwoRuns:
    """One finding per case. The first run detected all of them; the second evaluates some."""
    created = await two_runs(ana, owner)
    seeded = created.seeded
    await add_finding(owner, seeded, "corregido", detections=[(0, 1)])  # GET /orders, Cliente A
    await add_finding(
        owner,
        seeded,
        "otro-modulo",
        module="configuration",
        operation=None,
        identity="Anónimo",
        detections=[(0, 2)],
    )
    await add_finding(owner, seeded, "omitido", operation=USERS, detections=[(0, 3)])
    await add_finding(owner, seeded, "con-error", operation=NEW_ORDER, detections=[(0, 4)])
    # Two failure types on one cell: the second run finds one again and not the other.
    await add_finding(owner, seeded, "otra-vez", identity="Cliente B", detections=[(0, 5), (1, 30)])
    await add_finding(owner, seeded, "ya-no", identity="Cliente B", detections=[(0, 6)])
    await add_finding(
        owner,
        seeded,
        "aceptado",
        operation=USERS,
        identity="Cliente B",
        detections=[(0, 7)],
        status="accepted_risk",
        dismissal_reason="accepted_risk",
        justification="Lo cubre el WAF.",
    )
    await add_finding(
        owner,
        seeded,
        "regresion",
        operation=NEW_ORDER,
        identity="Cliente B",
        detections=[(0, 8)],
        status="regression",
    )
    await add_cells(
        owner,
        created.second,
        [
            ("object_access", ORDERS, "Cliente A", "own_data_only", "200 own_data_only", "pass"),
            ("object_access", USERS, "Cliente A", "denied", "expired", "skipped"),
            ("object_access", NEW_ORDER, "Cliente A", "allowed", "no_response", "error"),
            ("object_access", ORDERS, "Cliente B", "denied", "200 allowed", "fail"),
            ("object_access", USERS, "Cliente B", "denied", "403 denied", "pass"),
            ("object_access", NEW_ORDER, "Cliente B", "denied", "403 denied", "pass"),
        ],
    )
    return created


# ------------------------------------------------------------------ the rule (ADR-014)


async def test_only_what_was_evaluated_and_not_found_is_resolved(
    runs: TwoRuns, owner: AsyncEngine, scanner_engine: AsyncEngine
) -> None:
    resolved = await resolve(scanner_engine, runs)

    assert resolved == 3
    assert await states(owner, runs) == {
        "corregido": ("resolved", "not_detected"),  # a pass cell, not found
        "otro-modulo": ("persistent", None),  # its module did not run
        "omitido": ("persistent", None),  # skipped: not evaluated
        "con-error": ("persistent", None),  # error: not evaluated
        "otra-vez": ("persistent", None),  # found again
        "ya-no": ("resolved", "not_detected"),  # a fail cell, but for another failure
        "aceptado": ("accepted_risk", None),  # only open findings are resolved
        "regresion": ("resolved", "not_detected"),
    }


async def test_each_resolution_is_an_event_of_the_run(
    runs: TwoRuns, owner: AsyncEngine, scanner_engine: AsyncEngine
) -> None:
    await resolve(scanner_engine, runs)

    async with AsyncSession(owner) as db:
        finding = await db.get(Finding, runs.finding("regresion"))
        events = (
            await db.scalars(
                select(FindingEvent)
                .where(FindingEvent.finding_id == runs.finding("regresion"))
                .order_by(FindingEvent.id)
            )
        ).all()
    assert finding is not None
    assert finding.resolved_at is not None
    last = events[-1]
    assert (last.from_status, last.to_status, last.reason) == (
        "regression",
        "resolved",
        "not_detected",
    )
    assert (last.run_id, last.user_id) == (runs.run_id, None)  # caused by the run


async def test_resolving_twice_changes_nothing(
    runs: TwoRuns, owner: AsyncEngine, scanner_engine: AsyncEngine
) -> None:
    await resolve(scanner_engine, runs)
    before = await states(owner, runs)

    assert await resolve(scanner_engine, runs) == 0
    assert await states(owner, runs) == before


async def test_the_metric_keeps_the_days_of_the_first_resolution(
    runs: TwoRuns, owner: AsyncEngine, scanner_engine: AsyncEngine
) -> None:
    """RF-78, modelo.md 7.3: from the first detection, only the first time it is resolved."""
    async with await owner_session(owner) as db, db.begin():
        corrected = await db.get(Finding, runs.finding("corregido"))
        regression = await db.get(Finding, runs.finding("regresion"))
        assert corrected is not None and regression is not None
        corrected.detected_at = dt.datetime.now(dt.UTC) - dt.timedelta(days=12)
        # Resolved once already (12 days), then it came back.
        await db.execute(
            update(FindingMetric)
            .where(FindingMetric.id == regression.metric_id)
            .values(days_to_resolve=12, regressions=1)
        )
        today = await db.scalar(text("SELECT current_date"))

    await resolve(scanner_engine, runs)

    async with AsyncSession(owner) as db:
        days = dict(
            (
                await db.execute(
                    select(Finding.id, FindingMetric.days_to_resolve)
                    .join(FindingMetric, FindingMetric.id == Finding.metric_id)
                    .where(Finding.project_id == runs.project_id)
                )
            ).all()
        )
    detected = (dt.datetime.now(dt.UTC) - dt.timedelta(days=12)).date()
    assert days[runs.finding("corregido")] == (today - detected).days
    assert days[runs.finding("regresion")] == 12  # not overwritten
    assert days[runs.finding("otra-vez")] is None  # still open


# ------------------------------------------------------------------ reconciliation (CU-23)


async def test_a_run_that_stopped_beating_resolves_what_it_evaluated(
    runs: TwoRuns,
    owner: AsyncEngine,
    scanner_engine: AsyncEngine,
    run_queue: MemoryRunQueue,
    run_events: MemoryRunEvents,
) -> None:
    async with await owner_session(owner) as db, db.begin():
        await db.execute(
            text("UPDATE runs SET heartbeat_at = now() - interval '61 seconds' WHERE id = :id"),
            {"id": runs.run_id},
        )

    result = await reconcile(create_session_factory(scanner_engine), run_queue, run_events)

    assert result.expired == [runs.run_id]
    found = await states(owner, runs)
    assert [label for label, (status, _) in found.items() if status == "resolved"] == [
        "corregido",
        "ya-no",
        "regresion",
    ]


async def test_a_scanner_that_ends_a_run_already_failed_resolves_nothing(
    runs: TwoRuns, owner: AsyncEngine, scanner_engine: AsyncEngine, app: FastAPI
) -> None:
    """The reconciliation failed the run while its scanner was still alive: when the scanner
    ends, the run stays failed and the findings are not resolved a second time."""
    async with await owner_session(owner) as db, db.begin():
        await db.execute(
            update(Run)
            .where(Run.id == runs.run_id)
            .values(status="failed", end_reason="heartbeat_expired", finished_at=func.now())
        )
        run = await db.get(Run, runs.run_id)
    assert run is not None
    scanner = lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())

    await execution._finish(scanner, run, execution.Ending(RunStatus.COMPLETED, EndReason.NORMAL))

    async with AsyncSession(owner) as db:
        stored = await db.get(Run, runs.run_id)
    assert stored is not None
    assert (stored.status, stored.end_reason) == ("failed", "heartbeat_expired")
    assert {status for status, _ in (await states(owner, runs)).values()} == {
        "persistent",
        "regression",
        "accepted_risk",
    }


# ------------------------------------------------------------------ the lab, fixed (RF-68, RF-73)


@pytest.fixture
def switchable_lab() -> Iterator[tuple[LocalServer, FastAPI]]:
    """Its own lab, vulnerable at first: the test fixes it, so the shared ones stay as they are."""
    lab = build_lab(Mode.VULNERABLE)
    with LocalServer(lab) as server:
        yield server, lab


async def test_fixing_the_api_resolves_its_findings_and_breaking_it_again_reopens_them(
    ana: Analyst,
    switchable_lab: tuple[LocalServer, FastAPI],
    scanner_engine: AsyncEngine,
    app: FastAPI,
) -> None:
    server, lab = switchable_lab
    scanner: Scanner = lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())
    project = await lab_project(ana, server, lab)
    url = f"/projects/{project.id}/findings"

    async def snapshot() -> tuple[set[str], bool]:
        found: dict[str, Any] = (await ana.request("GET", url)).json()
        dashboard = (await ana.request("GET", f"/projects/{project.id}")).json()
        return {item["status"] for item in found["items"]}, dashboard["concluded"]

    await run_lab(scanner, project, lab)
    vulnerable = await snapshot()
    lab.state.mode = Mode.SECURE  # the analyst fixes the API
    fixed_run = await run_lab(scanner, project, lab)
    fixed = await snapshot()
    finding = (await ana.request("GET", url)).json()["items"][0]
    detail = (await ana.request("GET", f"{url}/{finding['id']}")).json()
    lab.state.mode = Mode.VULNERABLE  # and breaks it again
    await run_lab(scanner, project, lab)
    broken = await snapshot()

    assert vulnerable == ({"new"}, False)
    assert fixed == ({"resolved"}, True)  # RF-73: a completed run and nothing open
    assert broken == ({"regression"}, False)
    assert detail["resolution_reason"] == "not_detected"
    assert detail["resolved_at"] is not None
    assert detail["history"][-1]["reason"] == "not_detected"
    assert detail["history"][-1]["run"]["id"] == str(fixed_run)


# ------------------------------------------------------------------ administrative closure (RF-69)


PATHS: dict[str, Any] = cast(dict[str, Any], CONTRACT["paths"])


async def import_contract(analyst: Analyst, project_id: str, paths: dict[str, Any]) -> None:
    document = {**CONTRACT, "paths": paths}
    files = {"file": ("openapi.json", json.dumps(document).encode(), "application/json")}
    response = await analyst.request("POST", f"/projects/{project_id}/contracts", files=files)
    assert response.status_code == 201, response.text


async def test_retiring_an_operation_closes_its_open_findings(
    ana: Analyst, owner: AsyncEngine
) -> None:
    created = await two_runs(ana, owner)
    seeded = created.seeded
    await add_finding(owner, seeded, "abierto", operation=USERS, detections=[(0, 1)])
    await add_finding(
        owner,
        seeded,
        "aceptado",
        operation=USERS,
        identity="Cliente B",
        detections=[(0, 2)],
        status="accepted_risk",
        dismissal_reason="accepted_risk",
        justification="Lo cubre el WAF.",
    )
    await add_finding(owner, seeded, "sigue", operation=ORDERS, detections=[(0, 3)])
    url = f"/projects/{seeded.project.id}/findings"

    without_users = {k: v for k, v in PATHS.items() if k != "/users"}
    await import_contract(ana, seeded.project.id, without_users)
    closed = (await ana.request("GET", f"{url}/{seeded.findings['abierto']}")).json()
    await import_contract(ana, seeded.project.id, PATHS)  # it comes back

    assert await states(owner, created) == {
        "abierto": ("resolved", "operation_retired"),
        "aceptado": ("accepted_risk", None),  # only open findings are closed
        "sigue": ("persistent", None),
    }
    assert closed["resolved_at"] is not None
    assert closed["history"][-1] == {
        "from_status": "persistent",
        "to_status": "resolved",
        "reason": "operation_retired",
        "run": None,  # the analyst caused it, by importing
        "justification": None,
        "occurred_at": closed["history"][-1]["occurred_at"],
    }
    async with AsyncSession(owner) as db:
        days = await db.scalar(
            select(FindingMetric.days_to_resolve)
            .join(Finding, Finding.metric_id == FindingMetric.id)
            .where(Finding.id == created.finding("abierto"))
        )
    assert days is None  # not a fix (modelo.md 7.3)
