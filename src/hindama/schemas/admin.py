"""Schemas of `/admin/*` (contract: `AuditLogPage`, `AuditLogEntry`, `AuditDetails`, CU-21;
`AdminStats`, CU-20)."""

from datetime import date, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import MISSING, Field

from hindama.core.safe_http import BlockReason
from hindama.models.enums import (
    AuditAction,
    BlockStage,
    DismissalReason,
    Module,
    VerificationMethod,
)
from hindama.schemas.common import ContractModel
from hindama.schemas.projects import SeverityCount
from hindama.schemas.runs import RunLimits

StatsGroup = Literal["day", "week"]


class AuditDetails(ContractModel):
    """Only the members that apply to the action appear: `MISSING` leaves the rest out."""

    run_id: UUID | MISSING = MISSING
    source_run_id: UUID | MISSING = MISSING
    modules: list[Module] | MISSING = MISSING
    limits: RunLimits | MISSING = MISSING
    verification_method: VerificationMethod | MISSING = MISSING
    identity_id: UUID | MISSING = MISSING
    finding_id: UUID | MISSING = MISSING
    dismissal_reason: DismissalReason | MISSING = MISSING
    stage: BlockStage | MISSING = MISSING
    block_reason: BlockReason | MISSING = MISSING

    @classmethod
    def stored(cls, details: dict[str, Any]) -> "AuditDetails":
        """From the JSONB column. A member the catalog no longer knows is left out, not a 500."""
        return cls.model_validate({k: v for k, v in details.items() if k in cls.model_fields})


class AuditLogEntry(ContractModel):
    id: int = Field(ge=1)
    occurred_at: datetime
    action: AuditAction
    user_id: UUID | None
    project_id: UUID | None
    source_ip: str | None
    details: AuditDetails


class AuditLogPage(ContractModel):
    items: list[AuditLogEntry]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)


# ------------------------------------------------------------------ statistics (CU-20)


class AdminStatsPeriod(ContractModel):
    date_from: date
    date_to: date
    group: StatsGroup


class AdminStatsUsers(ContractModel):
    total: int = Field(ge=0)
    new: int = Field(ge=0)
    deleted: int = Field(ge=0)


class AdminStatsProjects(ContractModel):
    created: int = Field(ge=0)


class AdminStatsRuns(ContractModel):
    started: int = Field(ge=0)
    cancelled: int = Field(ge=0)
    failed: int = Field(ge=0)


class AdminStatsActivity(ContractModel):
    start: date
    new_users: int = Field(ge=0)
    deleted_accounts: int = Field(ge=0)
    projects_created: int = Field(ge=0)
    runs_started: int = Field(ge=0)
    runs_cancelled: int = Field(ge=0)
    runs_failed: int = Field(ge=0)


class ModuleCount(ContractModel):
    module: Module
    detected: int = Field(ge=1)


class OwaspCount(ContractModel):
    owasp_category: str
    detected: int = Field(ge=1)


class WeekCount(ContractModel):
    week: date
    detected: int = Field(ge=0)


class AdminStatsFindings(ContractModel):
    detected: int = Field(ge=0)
    resolved: int = Field(ge=0)
    regressions: int = Field(ge=0)
    average_days_to_resolve: float | None = Field(ge=0)
    by_severity: SeverityCount
    by_module: list[ModuleCount]
    by_owasp_category: list[OwaspCount]
    weekly: list[WeekCount]


class AdminStats(ContractModel):
    period: AdminStatsPeriod
    users: AdminStatsUsers
    projects: AdminStatsProjects
    runs: AdminStatsRuns
    activity: list[AdminStatsActivity]
    findings: AdminStatsFindings
