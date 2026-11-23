"""Schemas of `/admin/*` (contract: `AuditLogPage`, `AuditLogEntry`, `AuditDetails`; CU-21)."""

from datetime import datetime
from typing import Any
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
from hindama.schemas.runs import RunLimits


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
