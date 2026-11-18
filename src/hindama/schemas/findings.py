"""Schemas of `/findings` (components `RunRef`, `FindingSummary`, `Finding`, `Dismissal`,
`DismissalCreate`, `FindingOccurrence`, `Evidence`, `FindingEvent`, `FindingPage`,
`FindingOccurrencePage`).

The evidence comes from the analyst's API: masked by the scanner before it was stored (RN-11), but
untrusted. The frontend shows it as text.
"""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import AfterValidator, Field, StringConstraints
from pydantic_core import PydanticCustomError

from hindama.models.enums import (
    DismissalReason,
    FindingEventReason,
    FindingStatus,
    HttpMethod,
    Module,
    ResolutionReason,
    Severity,
)
from hindama.schemas.common import MULTI_LINE, ContractModel
from hindama.schemas.contracts import OperationRef
from hindama.schemas.runs import IdentityRef


class RunRef(ContractModel):
    id: UUID
    number: int = Field(ge=1)


class FindingSummary(ContractModel):
    """RF-65. Severity, classification and title are those of the latest occurrence."""

    id: UUID
    module: Module
    finding_type: str = Field(max_length=200)
    title: str
    severity: Severity
    owasp_category: str
    cwe: str | None
    status: FindingStatus
    operation: OperationRef | None  # None in API-wide findings
    identity: IdentityRef
    detected_at: datetime
    last_detected_at: datetime
    resolved_at: datetime | None
    first_run: RunRef
    last_run: RunRef


class EvidenceRequest(ContractModel):
    method: HttpMethod
    url: str
    headers: dict[str, str]
    body: str | None


class EvidenceResponse(ContractModel):
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    body: str
    body_truncated: bool


class Evidence(ContractModel):
    request: EvidenceRequest
    response: EvidenceResponse
    context: dict[str, Any]  # the module's own keys (`resource`, `control_identity`...)


class FindingOccurrence(ContractModel):
    run: RunRef
    severity: Severity
    explanation: str
    evidence: Evidence
    detected_at: datetime


class Dismissal(ContractModel):
    reason: DismissalReason
    justification: str
    dismissed_at: datetime


def _required_text(value: str) -> str:
    """Trimmed; nothing left is a missing justification (RN-09), not a short one."""
    stripped = value.strip()
    if not stripped:
        raise PydanticCustomError("missing", "Este campo es obligatorio.")
    return stripped


Justification = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2000, pattern=MULTI_LINE),
    AfterValidator(_required_text),
]


class DismissalCreate(ContractModel):
    """CU-16, RF-70: accept the risk or mark a false positive, always with a justification."""

    reason: DismissalReason
    justification: Justification


class FindingEvent(ContractModel):
    from_status: FindingStatus | None
    to_status: FindingStatus
    reason: FindingEventReason
    run: RunRef | None  # None: the analyst caused it
    justification: str | None
    occurred_at: datetime


class Finding(FindingSummary):
    """RF-62, RF-66, RF-72."""

    recommendation: str
    dismissal: Dismissal | None
    resolution_reason: ResolutionReason | None
    last_occurrence: FindingOccurrence
    history: list[FindingEvent]


class FindingPage(ContractModel):
    items: list[FindingSummary]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)


class FindingOccurrencePage(ContractModel):
    items: list[FindingOccurrence]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
