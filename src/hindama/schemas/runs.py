"""Schemas of `/runs` (components `RunCreate`, `RunLimitsInput`, `RunLimits`, `Run`, `RunProgress`,
`CreatedResourceCount`, `RunPage`, `IdentityRef`, `Result`, `ResultPage`). `RunSummary` lives
with the dashboard, which also uses it."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import Field, field_validator

from hindama.models.enums import EndReason, Module, RunStatus, Verdict
from hindama.schemas.common import ContractModel
from hindama.schemas.contracts import OperationRef
from hindama.schemas.projects import ContractVersionSummary, RunSummary, SeverityCount

# RF-47: defaults and caps of each limit.
DEFAULT_REQUESTS_PER_SECOND = 5
DEFAULT_CONCURRENCY = 2
MAX_REQUESTS = 5000
MAX_DURATION_MINUTES = 30

Modules = Annotated[list[Module], Field(min_length=1, json_schema_extra={"uniqueItems": True})]


class RunLimitsInput(ContractModel):
    requests_per_second: int = Field(default=DEFAULT_REQUESTS_PER_SECOND, ge=1, le=20)
    concurrency: int = Field(default=DEFAULT_CONCURRENCY, ge=1, le=5)
    max_requests: int = Field(default=MAX_REQUESTS, ge=1, le=MAX_REQUESTS)
    max_duration_minutes: int = Field(default=MAX_DURATION_MINUTES, ge=1, le=MAX_DURATION_MINUTES)


class RunLimits(ContractModel):
    requests_per_second: int = Field(ge=1, le=20)
    concurrency: int = Field(ge=1, le=5)
    max_requests: int = Field(ge=1, le=MAX_REQUESTS)
    max_duration_minutes: int = Field(ge=1, le=MAX_DURATION_MINUTES)


class RunCreate(ContractModel):
    modules: Annotated[
        list[Module],
        Field(min_length=1, max_length=len(Module), json_schema_extra={"uniqueItems": True}),
    ]
    limits: RunLimitsInput = Field(default_factory=RunLimitsInput)
    confirm_risk: bool = False

    @field_validator("modules")
    @classmethod
    def _unique(cls, value: list[Module]) -> list[Module]:
        if len(set(value)) != len(value):
            raise ValueError("modules no admite repetidos")
        return value


class RunProgress(ContractModel):
    status: RunStatus
    current_module: Module | None
    requests_sent: int = Field(ge=0)
    cells_planned: int = Field(ge=0)
    cells_evaluated: int = Field(ge=0)
    percent: int = Field(ge=0, le=100)
    findings_by_severity: SeverityCount
    updated_at: datetime


class CreatedResourceCount(ContractModel):
    pending: int = Field(ge=0)
    deleted: int = Field(ge=0)
    failed: int = Field(ge=0)


class Run(ContractModel):
    id: UUID
    number: int = Field(ge=1)
    status: RunStatus
    end_reason: EndReason | None
    modules: Modules
    limits: RunLimits
    risk_confirmed: bool
    contract_version: ContractVersionSummary | None
    source_run_id: UUID | None
    progress: RunProgress
    created_resources: CreatedResourceCount
    cancel_requested_at: datetime | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class RunPage(ContractModel):
    items: list[RunSummary]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)


class IdentityRef(ContractModel):
    id: UUID
    name: str
    deleted: bool  # deleted after the run; its cells are kept


class Result(ContractModel):
    """A cell of the identity × operation matrix (RF-64)."""

    module: Module
    operation: OperationRef | None  # None in API-wide checks (CORS)
    identity: IdentityRef
    expected: str = Field(max_length=200)
    observed: str = Field(max_length=200)
    verdict: Verdict
    evaluated_at: datetime


class ResultPage(ContractModel):
    items: list[Result]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
