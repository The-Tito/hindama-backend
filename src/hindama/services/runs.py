"""Runs (CU-12, CU-14, CU-15, CU-17; RF-44 to RF-47, RF-52, RF-64, RF-71, RN-01, RN-05, RN-07).

The API only creates the run and enqueues its id; the scanner executes it (ADR-012). The job is
enqueued before this transaction commits, so a failure of Redis rolls the run back and the project
never keeps a `queued` run without a job (RN-07). The scanner, in turn, waits a moment for the row
to become visible (scanner/execution.py).

Cancelling (RF-52, ADR-006 as implemented in task 3.3): a queued run ends here and now; a running
one keeps `cancel_requested_at` and its SAQ job is aborted, which cancels the scanner's task. The
row stays locked until this transaction commits, and the scanner reads the request under the same
lock, so it never misses it.
"""

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from hindama.core.errors import (
    ConflictError,
    FieldIssue,
    NotFoundError,
    ServiceUnavailableError,
    UnprocessableError,
)
from hindama.core.run_queue import QueueUnavailableError, RunQueue
from hindama.models import ContractVersion, Run
from hindama.models.enums import (
    ACTIVE_RUN_STATUSES,
    CreatedResourceStatus,
    DailyMetricName,
    EndReason,
    Module,
    RunStatus,
    Severity,
    Verdict,
)
from hindama.repositories import metrics
from hindama.repositories import projects as projects_repository
from hindama.repositories import runs as repository
from hindama.repositories.runs import Cell
from hindama.services.projects import MODULE_RISK, is_verified, module_availability, run_modules

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RunView:
    run: Run
    contract: ContractVersion | None
    findings: dict[Severity, int]
    created_resources: dict[CreatedResourceStatus, int]


async def _contract(session: AsyncSession, run: Run) -> ContractVersion | None:
    if run.contract_version_id is None:
        return None
    contract: ContractVersion | None = await session.scalar(
        select(ContractVersion)
        .options(defer(ContractVersion.document))
        .where(
            ContractVersion.project_id == run.project_id,
            ContractVersion.id == run.contract_version_id,
        )
    )
    return contract


async def _view(session: AsyncSession, run: Run) -> RunView:
    return RunView(
        run=run,
        contract=await _contract(session, run),
        findings=(await repository.findings_by_severity(session, [run.id]))[run.id],
        created_resources=await repository.created_resources(session, run.id),
    )


# ------------------------------------------------------------------ create (CU-12)


async def create_run(
    session: AsyncSession,
    queue: RunQueue,
    project_id: UUID,
    *,
    modules: Sequence[Module],
    limits: dict[str, Any],
    confirm_risk: bool,
    source_run_id: UUID | None = None,
) -> RunView:
    project = await repository.lock_project(session, project_id)
    if project is None:
        raise NotFoundError()
    if not is_verified(project):
        raise ConflictError(
            "project.not_verified",
            "Proyecto sin verificar",
            "Verifica la propiedad del dominio antes de ejecutar pruebas.",
        )
    if await projects_repository.has_active_run(session, project_id):
        raise ConflictError(
            "project.active_run",
            "Hay una ejecución activa",
            "Espera a que termine la ejecución activa o cancélala antes de lanzar otra.",
        )

    contract = await projects_repository.current_contract(session, project_id)
    configuration = await projects_repository.configuration(session, project_id)
    availability = {
        a.module: a for a in module_availability(True, contract is not None, configuration)
    }
    unavailable = [
        FieldIssue(f"modules.{index}", "run.module_unavailable", "Faltan requisitos del módulo.")
        for index, module in enumerate(modules)
        if not availability[module].available
    ]
    if unavailable:
        raise UnprocessableError(
            "run.module_unavailable",
            "Un módulo no cumple sus requisitos",
            "Revisa en el proyecto lo que le falta a cada módulo.",
            errors=unavailable,
        )
    risky = any(MODULE_RISK[module] != "low" for module in modules)
    if risky and not confirm_risk:
        raise UnprocessableError(
            "run.risk_not_confirmed",
            "Falta confirmar el riesgo",
            "Los módulos de riesgo medio o alto exigen confirmar la advertencia en cada ejecución.",
            errors=[
                FieldIssue("confirm_risk", "run.risk_not_confirmed", "Confirma la advertencia.")
            ],
        )

    ordered = run_modules({"modules": modules})
    run = Run(
        project_id=project_id,
        number=await repository.next_number(session, project_id),
        contract_version_id=None if contract is None else contract.id,
        source_run_id=source_run_id,
        # As validated (modelo.md 3.3): repeating a run is copying this field.
        config={
            "modules": [module.value for module in ordered],
            "limits": limits,
            "risk_confirmed": risky,
        },
    )
    session.add(run)
    await session.flush()
    # Same transaction: a run that Redis rolls back is not counted (RF-78).
    await metrics.increment_daily(session, DailyMetricName.RUNS_STARTED)
    try:
        run.job_id = await queue.enqueue(run.id)
    except QueueUnavailableError as error:
        log.warning("run_queue_unavailable", project_id=str(project_id), error=str(error))
        raise ServiceUnavailableError() from error
    await session.flush()
    await session.refresh(run)
    # The router audits it (`run_launched`, RF-81).
    log.info(
        "run_created",
        project_id=str(project_id),
        run_id=str(run.id),
        source_run_id=None if source_run_id is None else str(source_run_id),
        modules=[module.value for module in ordered],
    )
    return RunView(
        run=run,
        contract=contract,
        findings=dict.fromkeys(Severity, 0),
        created_resources=dict.fromkeys(CreatedResourceStatus, 0),
    )


# ------------------------------------------------------------------ rerun (CU-17)


async def rerun_run(
    session: AsyncSession, queue: RunQueue, project_id: UUID, run_id: UUID, *, confirm_risk: bool
) -> RunView:
    """RF-71: a new run with the modules and limits of `run_id`, validated as a new one.

    The risk confirmation is asked again (RF-46), a module that no longer meets its requirements
    is refused instead of dropped, and an active `run_id` is refused as the project's active run
    (RN-07).
    """
    source = await repository.get(session, project_id, run_id)
    if source is None:
        raise NotFoundError()
    return await create_run(
        session,
        queue,
        project_id,
        modules=[Module(module) for module in source.config["modules"]],
        limits=dict(source.config["limits"]),
        confirm_risk=confirm_risk,
        source_run_id=source.id,
    )


# ------------------------------------------------------------------ cancel (CU-14)


@dataclass(frozen=True, slots=True)
class Cancellation:
    view: RunView
    ended: bool  # the run ended here (it was queued): nobody else publishes its `end`
    first: bool  # this request asked for it; a repeated cancel is not audited again (RF-81)


async def cancel_run(
    session: AsyncSession, queue: RunQueue, project_id: UUID, run_id: UUID
) -> Cancellation:
    run = await repository.lock(session, project_id, run_id)
    if run is None:
        raise NotFoundError()
    if run.status not in ACTIVE_RUN_STATUSES:
        raise ConflictError(
            "run.not_active",
            "La ejecución ya terminó",
            "Solo se puede cancelar una ejecución en cola o en curso.",
        )
    first = run.cancel_requested_at is None
    if first:  # repeating it answers the same (contract)
        run.cancel_requested_at = func.now()
    queued = run.status == RunStatus.QUEUED
    if queued:
        run.status = RunStatus.CANCELLED
        run.end_reason = EndReason.CANCELLED_BY_USER
        run.finished_at = func.now()
        await metrics.increment_daily(session, DailyMetricName.RUNS_CANCELLED)
    try:
        await queue.abort(run.id)
    except QueueUnavailableError as error:
        log.warning("run_queue_unavailable", project_id=str(project_id), error=str(error))
        if not queued:  # nothing would stop the scanner: roll back and say so
            raise ServiceUnavailableError() from error
        # A queued run is already over: if its job still runs, the scanner skips it.
    await session.flush()
    await session.refresh(run)
    log.info(
        "run_cancel_requested",
        project_id=str(project_id),
        run_id=str(run_id),
        status=run.status,
    )
    return Cancellation(view=await _view(session, run), ended=queued, first=first)


# ------------------------------------------------------------------ queries


async def get_run(session: AsyncSession, project_id: UUID, run_id: UUID) -> RunView:
    run = await repository.get(session, project_id, run_id)
    if run is None:
        raise NotFoundError()
    return await _view(session, run)


async def list_runs(
    session: AsyncSession,
    project_id: UUID,
    *,
    statuses: Collection[RunStatus],
    page: int,
    page_size: int,
) -> tuple[Sequence[Run], int, dict[UUID, dict[Severity, int]]]:
    if await projects_repository.get(session, project_id) is None:
        raise NotFoundError()
    rows, total = await repository.page(session, project_id, statuses, page, page_size)
    findings = await repository.findings_by_severity(session, [row.id for row in rows])
    return rows, total, findings


async def list_results(
    session: AsyncSession,
    project_id: UUID,
    run_id: UUID,
    *,
    modules: Collection[Module],
    verdicts: Collection[Verdict],
    identity_id: UUID | None,
    operation_id: UUID | None,
    page: int,
    page_size: int,
) -> tuple[list[Cell], int]:
    """RF-64. An active run returns the cells finished so far: a cell is written only once it is
    complete. A filter by an identity or operation of another project simply matches nothing."""
    if await repository.get(session, project_id, run_id) is None:
        raise NotFoundError()
    return await repository.results(
        session,
        project_id,
        run_id,
        modules=modules,
        verdicts=verdicts,
        identity_id=identity_id,
        operation_id=operation_id,
        page=page,
        page_size=page_size,
    )
