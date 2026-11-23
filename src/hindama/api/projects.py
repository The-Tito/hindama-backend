"""`/projects` and `/projects/{project_id}` (CU-05, CU-06; RF-10 to RF-16)."""

from collections.abc import Mapping
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status

from hindama.api.accounts import TermsVersion
from hindama.api.dependencies import Analyst, Audit, DbSession
from hindama.config import Settings
from hindama.core.destinations import InvalidUrlError, UrlProblem, parse_base_url
from hindama.core.errors import UnprocessableError
from hindama.core.safe_http import BlockReason
from hindama.models import Run as RunRow
from hindama.models.enums import AuditAction, BlockStage, EndReason, RunStatus, Severity
from hindama.repositories.projects import Sort
from hindama.schemas.common import SINGLE_LINE, Warning
from hindama.schemas.projects import (
    ContractVersionSummary,
    ModuleAvailability,
    Project,
    ProjectCreate,
    ProjectPage,
    ProjectSummary,
    ProjectUpdate,
    RunSummary,
    SeverityCount,
)
from hindama.services import projects as service
from hindama.services.projects import WARNING_MESSAGES, Dashboard, UrlPolicy, run_modules

router = APIRouter(tags=["Projects"])

# convenciones.md 7. Without a bound, a huge page overflowed PostgreSQL's int64 OFFSET (500).
MAX_PAGE = 10_000


def get_url_policy(request: Request) -> UrlPolicy:
    settings: Settings = request.app.state.settings
    return UrlPolicy(
        resolver=request.app.state.resolver,
        own_addresses=tuple(settings.own_ip_addresses),
        address_policy=getattr(request.app.state, "address_policy", None),
    )


Destinations = Annotated[UrlPolicy, Depends(get_url_policy)]


def severity_count(counts: Mapping[Severity, int]) -> SeverityCount:
    return SeverityCount(
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
        total=sum(counts.values()),
    )


def run_summary(run: RunRow, findings: Mapping[Severity, int]) -> RunSummary:
    """RF-63: the dashboard's `last_run` and each item of `listRuns`."""
    return RunSummary(
        id=run.id,
        number=run.number,
        status=RunStatus(run.status),
        end_reason=None if run.end_reason is None else EndReason(run.end_reason),
        modules=run_modules(run.config),
        requests_sent=run.requests_sent,
        findings_by_severity=severity_count(findings),
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


def _project(view: Dashboard) -> Project:
    project = view.project
    contract = view.current_contract
    run = view.last_run
    counts = view.open_findings
    return Project(
        id=project.id,
        name=project.name,
        description=project.description,
        base_url=project.base_url,
        host=project.host,
        verification_status=project.verification_status,
        verified_at=project.verified_at,
        concluded=view.concluded,
        current_contract=None
        if contract is None
        else ContractVersionSummary(
            id=contract.id,
            number=contract.number,
            source=contract.source,
            openapi_version=contract.openapi_version,
            operation_count=contract.operation_count,
            imported_at=contract.imported_at,
        ),
        last_run=None if run is None else run_summary(run, view.last_run_findings),
        open_findings_by_severity=severity_count(counts),
        modules=[
            ModuleAvailability(
                module=m.module,
                risk=m.risk,
                available=m.available,
                missing=m.missing,
            )
            for m in view.modules
        ],
        warnings=[
            Warning(code=code, message=WARNING_MESSAGES[code], location=None)
            for code in view.warnings
        ],
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


@router.get("/projects", operation_id="listProjects", summary="Proyectos del analista")
async def list_projects(
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    sort: Sort = "-created_at",
) -> ProjectPage:
    rows, total = await service.list_projects(db, sort, page, page_size)
    return ProjectPage(
        items=[
            ProjectSummary(
                id=row.project.id,
                name=row.project.name,
                base_url=row.project.base_url,
                verification_status=row.project.verification_status,
                concluded=row.concluded,
                last_run_at=row.last_run_at,
                open_findings=row.open_findings,
                created_at=row.project.created_at,
            )
            for row in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/projects",
    operation_id="createProject",
    summary="Crear un proyecto",
    status_code=status.HTTP_201_CREATED,
)
async def create_project(
    body: ProjectCreate,
    user: Analyst,
    db: DbSession,
    response: Response,
    terms_version: TermsVersion,
    destinations: Destinations,
    audit: Audit,
) -> Project:
    try:
        view = await service.create_project(
            db,
            user,
            name=body.name,
            description=body.description,
            base_url=body.base_url,
            terms_version=terms_version,
            url_policy=destinations,
        )
    except UnprocessableError as error:
        await _audit_url_block(audit, error, body.base_url, project_id=None)
        raise
    await audit.record(
        AuditAction.PROJECT_CREATED, project_id=view.project.id, host=view.project.host
    )
    response.headers["Location"] = f"/projects/{view.project.id}"
    return _project(view)


async def _audit_url_block(
    audit: Audit, error: UnprocessableError, base_url: str, project_id: UUID | None
) -> None:
    """A base URL that points to a forbidden address is a blocked destination (RF-11, RF-81).

    The request fails with 422, so the entry goes in its own transaction."""
    if error.code != UrlProblem.DESTINATION_NOT_ALLOWED.value:
        return
    try:
        host = parse_base_url(base_url).host
    except InvalidUrlError:  # pragma: no cover - the URL parsed before its destination failed
        return
    await audit.record_detached(
        AuditAction.DESTINATION_BLOCKED,
        project_id=project_id,
        host=host,
        stage=BlockStage.PROJECT_URL,
        block_reason=BlockReason.ADDRESS_NOT_ALLOWED,
    )


@router.get("/projects/{project_id}", operation_id="getProject", summary="Dashboard del proyecto")
async def get_project(project_id: UUID, _: Analyst, db: DbSession) -> Project:
    return _project(await service.dashboard(db, project_id))


@router.patch(
    "/projects/{project_id}",
    operation_id="updateProject",
    summary="Editar nombre, descripción o URL base",
)
async def update_project(
    project_id: UUID,
    body: ProjectUpdate,
    _: Analyst,
    db: DbSession,
    destinations: Destinations,
    audit: Audit,
) -> Project:
    changes = body.model_dump(exclude_unset=True)
    try:
        return _project(await service.update_project(db, project_id, changes, destinations))
    except UnprocessableError as error:
        if "base_url" in changes:
            await _audit_url_block(audit, error, changes["base_url"], project_id=project_id)
        raise


@router.delete(
    "/projects/{project_id}",
    operation_id="deleteProject",
    summary="Eliminar un proyecto",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_project(
    project_id: UUID,
    confirmation: Annotated[str, Query(min_length=1, max_length=100, pattern=SINGLE_LINE)],
    _: Analyst,
    db: DbSession,
    audit: Audit,
) -> Response:
    host = await service.delete_project(db, project_id, confirmation)
    await audit.record(AuditAction.PROJECT_DELETED, project_id=project_id, host=host)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
