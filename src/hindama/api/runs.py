"""`/projects/{project_id}/runs` (CU-12 to CU-15, CU-17; RF-44 to RF-47, RF-51, RF-52, RF-63, RF-64,
RF-71)."""

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Header, Query, Request, Response, status
from pydantic import AfterValidator

from hindama.api.dependencies import DATABASE_UNAVAILABLE, Analyst, Audit, DbSession
from hindama.api.projects import MAX_PAGE, run_summary, severity_count
from hindama.api.run_stream import STREAM_HEADERS, EventStreamResponse, first_event_id, stream
from hindama.core.errors import NotFoundError
from hindama.core.run_events import RunEvent, RunEvents
from hindama.core.run_queue import RunQueue
from hindama.db.session import set_rls_context
from hindama.models import Identity, Operation
from hindama.models import Result as ResultRow
from hindama.models.enums import (
    AuditAction,
    CreatedResourceStatus,
    EndReason,
    HttpMethod,
    Module,
    RunStatus,
    Verdict,
)
from hindama.schemas.contracts import OperationRef
from hindama.schemas.projects import ContractVersionSummary
from hindama.schemas.runs import (
    CreatedResourceCount,
    CreatedResourceFailure,
    IdentityRef,
    Result,
    ResultPage,
    Run,
    RunCreate,
    RunLimits,
    RunPage,
    RunProgress,
    RunRerun,
)
from hindama.services import runs as service
from hindama.services.projects import run_modules
from hindama.services.runs import RunView

log = structlog.get_logger(__name__)

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
            failed_items=[
                CreatedResourceFailure(
                    operation_id=row.operation_id, location=row.location, last_error=row.last_error
                )
                for row in view.failed_resources
            ],
        ),
        cancel_requested_at=run.cancel_requested_at,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


def unique[T](value: list[T]) -> list[T]:
    """A repeated query value is a 422 (`uniqueItems` in the contract)."""

    if len(set(value)) != len(value):
        raise ValueError("no admite valores repetidos")
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
        AfterValidator(unique),
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
    audit: Audit,
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
    await _audit_launch(audit, view)
    response.headers["Location"] = f"/projects/{project_id}/runs/{view.run.id}"
    return _run(view)


async def _audit_launch(audit: Audit, view: RunView) -> None:
    """RF-81: modules and limits of the run, with the HMAC of the project's host."""
    run = view.run
    await audit.record_on_project(
        AuditAction.RUN_LAUNCHED,
        run.project_id,
        run_id=run.id,
        source_run_id=run.source_run_id,
        modules=list(run.config["modules"]),
        limits=dict(run.config["limits"]),
    )


@router.post(
    "/projects/{project_id}/runs/{run_id}/rerun",
    operation_id="rerunRun",
    summary="Volver a probar",
    status_code=status.HTTP_202_ACCEPTED,
)
async def rerun_run(
    project_id: UUID,
    run_id: UUID,
    body: RunRerun,
    _: Analyst,
    db: DbSession,
    request: Request,
    response: Response,
    audit: Audit,
) -> Run:
    queue: RunQueue = request.app.state.run_queue
    view = await service.rerun_run(db, queue, project_id, run_id, confirm_risk=body.confirm_risk)
    await _audit_launch(audit, view)
    response.headers["Location"] = f"/projects/{project_id}/runs/{view.run.id}"
    return _run(view)


@router.get(
    "/projects/{project_id}/runs/{run_id}",
    operation_id="getRun",
    summary="Consultar una ejecución",
)
async def get_run(project_id: UUID, run_id: UUID, _: Analyst, db: DbSession) -> Run:
    return _run(await service.get_run(db, project_id, run_id))


@router.post(
    "/projects/{project_id}/runs/{run_id}/cancel",
    operation_id="cancelRun",
    summary="Cancelar una ejecución",
    status_code=status.HTTP_202_ACCEPTED,
)
async def cancel_run(
    project_id: UUID,
    run_id: UUID,
    _: Analyst,
    db: DbSession,
    request: Request,
    background: BackgroundTasks,
    audit: Audit,
) -> Run:
    queue: RunQueue = request.app.state.run_queue
    cancellation = await service.cancel_run(db, queue, project_id, run_id)
    if cancellation.first:
        await audit.record_on_project(AuditAction.RUN_CANCELLED, project_id, run_id=run_id)
    if cancellation.ended:
        # A queued run ended here: tell its streams, once the transaction is committed.
        events: RunEvents = request.app.state.run_events
        background.add_task(events.publish, run_id, RunEvent.END)
    return _run(cancellation.view)


# The contract's pattern: no control characters (they would break the stream's lines).
_EVENT_ID_PATTERN = r"^[^\x00-\x1F\x7F]*$"


@router.get(
    "/projects/{project_id}/runs/{run_id}/events",
    operation_id="streamRunEvents",
    summary="Progreso en tiempo real (SSE)",
    response_class=EventStreamResponse,
    responses={
        200: {
            "description": "Stream de eventos.",
            "content": {"text/event-stream": {"schema": {"type": "string"}}},
        }
    },
)
async def stream_run_events(
    project_id: UUID,
    run_id: UUID,
    user: Analyst,
    db: DbSession,
    request: Request,
    last_event_id: Annotated[
        str, Header(alias="Last-Event-ID", max_length=64, pattern=_EVENT_ID_PATTERN)
    ] = "",
) -> EventStreamResponse:
    await service.get_run(db, project_id, run_id)  # 404 before streaming (RN-02)
    session_factory = request.app.state.session_factory

    async def load() -> RunView | None:
        # The request's transaction is over: each reading opens its own, as the same caller.
        try:
            async with session_factory() as session, session.begin():
                await set_rls_context(
                    session, cognito_sub=user.cognito_sub, role=user.role, user_id=user.id
                )
                return await service.get_run(session, project_id, run_id)
        except NotFoundError:
            return None
        except DATABASE_UNAVAILABLE as error:
            # The stream closes; the browser reconnects (CU-13 A1).
            log.warning("database_unavailable", error=type(error).__name__)
            return None

    events: RunEvents = request.app.state.run_events
    content = stream(events, run_id, load, _run, first_event_id(last_event_id))
    return EventStreamResponse(content, headers=STREAM_HEADERS)


def operation_ref(operation: Operation | None) -> OperationRef | None:
    if operation is None:
        return None
    return OperationRef(id=operation.id, method=HttpMethod(operation.method), path=operation.path)


def identity_ref(identity: Identity) -> IdentityRef:
    """A deleted identity keeps its cells and findings (modelo.md section 7.1)."""
    return IdentityRef(id=identity.id, name=identity.name, deleted=identity.deleted_at is not None)


def _result(row: ResultRow, operation: Operation | None, identity: Identity) -> Result:
    return Result(
        module=Module(row.module),
        operation=operation_ref(operation),
        identity=identity_ref(identity),
        expected=row.expected,
        observed=row.observed,
        verdict=Verdict(row.verdict),
        evaluated_at=row.evaluated_at,
    )


@router.get(
    "/projects/{project_id}/runs/{run_id}/results",
    operation_id="listRunResults",
    summary="Matriz identidad × operación",
)
async def list_run_results(
    project_id: UUID,
    run_id: UUID,
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 100,
    modules: Annotated[
        list[Module],
        AfterValidator(unique),
        Query(alias="module", json_schema_extra={"uniqueItems": True}),
    ] = [],  # noqa: B006 - FastAPI copies the default; a query list is never shared
    verdicts: Annotated[
        list[Verdict],
        AfterValidator(unique),
        Query(alias="verdict", json_schema_extra={"uniqueItems": True}),
    ] = [],  # noqa: B006
    identity_id: UUID | None = None,
    operation_id: UUID | None = None,
) -> ResultPage:
    rows, total = await service.list_results(
        db,
        project_id,
        run_id,
        modules=modules,
        verdicts=verdicts,
        identity_id=identity_id,
        operation_id=operation_id,
        page=page,
        page_size=page_size,
    )
    return ResultPage(
        items=[_result(*row) for row in rows], total=total, page=page, page_size=page_size
    )
