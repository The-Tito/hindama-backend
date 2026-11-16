"""`/projects/{project_id}/runs` (CU-12, CU-13; RF-44 to RF-47, RF-51, RF-63)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response, status
from pydantic import AfterValidator

from hindama.api.dependencies import Analyst, DbSession
from hindama.api.projects import MAX_PAGE, run_summary, severity_count
from hindama.core.run_queue import RunQueue
from hindama.models.enums import CreatedResourceStatus, EndReason, Module, RunStatus
from hindama.schemas.projects import ContractVersionSummary
from hindama.schemas.runs import (
    CreatedResourceCount,
    Run,
    RunCreate,
    RunLimits,
    RunPage,
    RunProgress,
)
from hindama.services import runs as service
from hindama.services.projects import run_modules
from hindama.services.runs import RunView

router = APIRouter(tags=["Runs"])


def _percent(view: RunView) -> int:
    """RF-51. 100 only when the run completed normally; otherwise where it got to."""
    run = view.run
    if run.status == RunStatus.COMPLETED and run.end_reason == EndReason.NORMAL:
        return 100
    if run.cells_planned == 0:
        return 0
    return min(run.cells_evaluated * 100 // run.cells_planned, 99)


def _run(view: RunView) -> Run:
    run = view.run
    contract = view.contract
    counts = view.created_resources
    return Run(
        id=run.id,
        number=run.number,
        status=RunStatus(run.status),
        end_reason=None if run.end_reason is None else EndReason(run.end_reason),
        modules=run_modules(run.config),
        limits=RunLimits(**run.config["limits"]),
        risk_confirmed=bool(run.config.get("risk_confirmed", False)),
        contract_version=None
        if contract is None
        else ContractVersionSummary(
            id=contract.id,
            number=contract.number,
            source=contract.source,
            openapi_version=contract.openapi_version,
            operation_count=contract.operation_count,
            imported_at=contract.imported_at,
        ),
        source_run_id=run.source_run_id,
        progress=RunProgress(
            status=RunStatus(run.status),
            current_module=None if run.current_module is None else Module(run.current_module),
            requests_sent=run.requests_sent,
            cells_planned=run.cells_planned,
            cells_evaluated=run.cells_evaluated,
            percent=_percent(view),
            findings_by_severity=severity_count(view.findings),
            updated_at=run.finished_at or run.heartbeat_at or run.started_at or run.created_at,
        ),
        created_resources=CreatedResourceCount(
            pending=counts[CreatedResourceStatus.PENDING],
            deleted=counts[CreatedResourceStatus.DELETED],
            failed=counts[CreatedResourceStatus.FAILED],
        ),
        cancel_requested_at=run.cancel_requested_at,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


def _unique(value: list[RunStatus]) -> list[RunStatus]:
    if len(set(value)) != len(value):
        raise ValueError("status no admite repetidos")
    return value


@router.get(
    "/projects/{project_id}/runs",
    operation_id="listRuns",
    summary="Ejecuciones del proyecto",
)
async def list_runs(
    project_id: UUID,
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    statuses: Annotated[
        list[RunStatus],
        AfterValidator(_unique),
        Query(alias="status", json_schema_extra={"uniqueItems": True}),
    ] = [],  # noqa: B006 - FastAPI copies the default; a query list is never shared
) -> RunPage:
    rows, total, findings = await service.list_runs(
        db, project_id, statuses=statuses, page=page, page_size=page_size
    )
    return RunPage(
        items=[run_summary(row, findings[row.id]) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/projects/{project_id}/runs",
    operation_id="createRun",
    summary="Lanzar una ejecución",
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_run(
    project_id: UUID,
    body: RunCreate,
    _: Analyst,
    db: DbSession,
    request: Request,
    response: Response,
) -> Run:
    queue: RunQueue = request.app.state.run_queue
    view = await service.create_run(
        db,
        queue,
        project_id,
        modules=body.modules,
        limits=body.limits.model_dump(),
        confirm_risk=body.confirm_risk,
    )
    response.headers["Location"] = f"/projects/{project_id}/runs/{view.run.id}"
    return _run(view)


@router.get(
    "/projects/{project_id}/runs/{run_id}",
    operation_id="getRun",
    summary="Consultar una ejecución",
)
async def get_run(project_id: UUID, run_id: UUID, _: Analyst, db: DbSession) -> Run:
    return _run(await service.get_run(db, project_id, run_id))
