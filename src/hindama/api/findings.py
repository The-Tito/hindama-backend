"""`/projects/{project_id}/findings` (CU-15; RF-62, RF-65, RF-66, RF-72)."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import AfterValidator

from hindama.api.dependencies import Analyst, DbSession
from hindama.api.projects import MAX_PAGE
from hindama.api.runs import identity_ref, operation_ref, unique
from hindama.models.enums import (
    DismissalReason,
    FindingEventReason,
    FindingStatus,
    HttpMethod,
    Module,
    ResolutionReason,
    Severity,
)
from hindama.repositories.findings import EventRow, FindingRow, OccurrenceRow
from hindama.schemas.findings import (
    Dismissal,
    Evidence,
    EvidenceRequest,
    EvidenceResponse,
    Finding,
    FindingEvent,
    FindingOccurrence,
    FindingOccurrencePage,
    FindingPage,
    FindingSummary,
    RunRef,
)
from hindama.services import findings as service

router = APIRouter(tags=["Findings"])


def _summary(row: FindingRow) -> FindingSummary:
    finding = row.finding
    return FindingSummary(
        id=finding.id,
        module=Module(finding.module),
        finding_type=finding.finding_type,
        title=finding.title,
        severity=Severity(finding.severity),
        owasp_category=finding.owasp_category,
        cwe=finding.cwe,
        status=FindingStatus(finding.status),
        operation=operation_ref(row.operation),
        identity=identity_ref(row.identity),
        detected_at=finding.detected_at,
        last_detected_at=row.last_detected_at,
        resolved_at=finding.resolved_at,
        first_run=RunRef(id=finding.first_run_id, number=row.first_run_number),
        last_run=RunRef(id=finding.last_run_id, number=row.last_run_number),
    )


def _evidence(stored: dict[str, Any]) -> Evidence:
    """As `scanner/evidence.Masker` stores it: `request`, `response` and the module's own keys at
    the top level, which the contract groups in `context`."""
    request, response = stored["request"], stored["response"]
    return Evidence(
        request=EvidenceRequest(
            method=HttpMethod(request["method"]),
            url=request["url"],
            headers=request["headers"],
            body=request.get("body"),
        ),
        response=EvidenceResponse(
            status_code=response["status_code"],
            headers=response["headers"],
            body=response["body"],
            body_truncated=response["body_truncated"],
        ),
        context={key: value for key, value in stored.items() if key not in ("request", "response")},
    )


def _occurrence(row: OccurrenceRow) -> FindingOccurrence:
    occurrence = row.occurrence
    return FindingOccurrence(
        run=RunRef(id=occurrence.run_id, number=row.run_number),
        severity=Severity(occurrence.severity),
        explanation=occurrence.explanation,
        evidence=_evidence(occurrence.evidence),
        detected_at=occurrence.detected_at,
    )


def _event(row: EventRow) -> FindingEvent:
    event = row.event
    return FindingEvent(
        from_status=None if event.from_status is None else FindingStatus(event.from_status),
        to_status=FindingStatus(event.to_status),
        reason=FindingEventReason(event.reason),
        run=None
        if event.run_id is None or row.run_number is None
        else RunRef(id=event.run_id, number=row.run_number),
        justification=event.justification,
        occurred_at=event.occurred_at,
    )


def _finding(view: service.FindingView) -> Finding:
    finding = view.row.finding
    history = [_event(row) for row in view.history]
    dismissal = None
    if finding.dismissal_reason is not None and finding.justification is not None:
        # When it was dismissed: the event that moved it to accepted_risk (RF-72).
        dismissed_at = next(
            (
                e.occurred_at
                for e in reversed(history)
                if e.to_status == FindingStatus.ACCEPTED_RISK
            ),
            finding.detected_at,
        )
        dismissal = Dismissal(
            reason=DismissalReason(finding.dismissal_reason),
            justification=finding.justification,
            dismissed_at=dismissed_at,
        )
    return Finding(
        **_summary(view.row).model_dump(),
        recommendation=finding.recommendation,
        dismissal=dismissal,
        resolution_reason=None
        if finding.resolution_reason is None
        else ResolutionReason(finding.resolution_reason),
        last_occurrence=_occurrence(view.last_occurrence),
        history=history,
    )


@router.get(
    "/projects/{project_id}/findings",
    operation_id="listFindings",
    summary="Hallazgos del proyecto",
)
async def list_findings(
    project_id: UUID,
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    modules: Annotated[
        list[Module],
        AfterValidator(unique),
        Query(alias="module", json_schema_extra={"uniqueItems": True}),
    ] = [],  # noqa: B006 - FastAPI copies the default; a query list is never shared
    severities: Annotated[
        list[Severity],
        AfterValidator(unique),
        Query(alias="severity", json_schema_extra={"uniqueItems": True}),
    ] = [],  # noqa: B006
    statuses: Annotated[
        list[FindingStatus],
        AfterValidator(unique),
        Query(alias="status", json_schema_extra={"uniqueItems": True}),
    ] = [],  # noqa: B006
    run_id: UUID | None = None,
    identity_id: UUID | None = None,
    operation_id: UUID | None = None,
) -> FindingPage:
    rows, total = await service.list_findings(
        db,
        project_id,
        modules=modules,
        severities=severities,
        statuses=statuses,
        run_id=run_id,
        identity_id=identity_id,
        operation_id=operation_id,
        page=page,
        page_size=page_size,
    )
    return FindingPage(
        items=[_summary(row) for row in rows], total=total, page=page, page_size=page_size
    )


@router.get(
    "/projects/{project_id}/findings/{finding_id}",
    operation_id="getFinding",
    summary="Detalle de un hallazgo",
)
async def get_finding(project_id: UUID, finding_id: UUID, _: Analyst, db: DbSession) -> Finding:
    return _finding(await service.get_finding(db, project_id, finding_id))


@router.get(
    "/projects/{project_id}/findings/{finding_id}/occurrences",
    operation_id="listFindingOccurrences",
    summary="Ocurrencias de un hallazgo",
)
async def list_finding_occurrences(
    project_id: UUID,
    finding_id: UUID,
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=20)] = 10,
) -> FindingOccurrencePage:
    rows, total = await service.list_occurrences(
        db, project_id, finding_id, page=page, page_size=page_size
    )
    return FindingOccurrencePage(
        items=[_occurrence(row) for row in rows], total=total, page=page, page_size=page_size
    )
