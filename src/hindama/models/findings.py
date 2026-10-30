"""Finding tracking: logical finding + occurrence per run + event per status change (ADR-014)."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from hindama.models.base import MAX_EVIDENCE_BYTES, Base, created_at, one_of, uuid_pk
from hindama.models.enums import (
    DismissalReason,
    FindingEventReason,
    FindingStatus,
    Module,
    ResolutionReason,
    Severity,
)
from hindama.models.projects import project_fk


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "id"),
        # The fingerprint (RF-68). operation_id is NULL for API-wide findings.
        UniqueConstraint(
            "project_id",
            "module",
            "finding_type",
            "operation_id",
            "identity_id",
            postgresql_nulls_not_distinct=True,
        ),
        ForeignKeyConstraint(
            ["project_id", "operation_id"], ["operations.project_id", "operations.id"]
        ),
        ForeignKeyConstraint(
            ["project_id", "identity_id"], ["identities.project_id", "identities.id"]
        ),
        ForeignKeyConstraint(["project_id", "first_run_id"], ["runs.project_id", "runs.id"]),
        ForeignKeyConstraint(["project_id", "last_run_id"], ["runs.project_id", "runs.id"]),
        CheckConstraint(one_of("module", Module), name="module"),
        CheckConstraint(one_of("severity", Severity), name="severity"),
        CheckConstraint(one_of("status", FindingStatus), name="status"),
        CheckConstraint(one_of("dismissal_reason", DismissalReason), name="dismissal_reason"),
        CheckConstraint(one_of("resolution_reason", ResolutionReason), name="resolution_reason"),
        # Accepting a risk requires a reason and a non-empty justification (RF-70, RN-09).
        CheckConstraint(
            "(status = 'accepted_risk') = (dismissal_reason IS NOT NULL)"
            " AND (dismissal_reason IS NULL) = (justification IS NULL)"
            " AND (justification IS NULL OR char_length(btrim(justification)) > 0)",
            name="dismissal_consistent",
        ),
        CheckConstraint(
            "(status = 'resolved') = (resolution_reason IS NOT NULL)"
            " AND (status <> 'resolved' OR resolved_at IS NOT NULL)",
            name="resolution_consistent",
        ),
        Index(None, "project_id", "status"),
    )

    id: Mapped[UUID] = uuid_pk()
    project_id: Mapped[UUID] = project_fk()
    module: Mapped[str]
    finding_type: Mapped[
        str
    ]  # stable code from the module's catalog, e.g. sql_injection.parameter.q
    operation_id: Mapped[UUID | None]
    identity_id: Mapped[UUID]
    severity: Mapped[str]
    owasp_category: Mapped[str]
    cwe: Mapped[str | None]
    title: Mapped[str]
    recommendation: Mapped[str]
    status: Mapped[str]
    dismissal_reason: Mapped[str | None]
    justification: Mapped[str | None]
    resolution_reason: Mapped[str | None]
    detected_at: Mapped[datetime] = created_at()
    resolved_at: Mapped[datetime | None]
    first_run_id: Mapped[UUID]
    last_run_id: Mapped[UUID]
    metric_id: Mapped[UUID] = mapped_column(ForeignKey("finding_metrics.id"))


class FindingOccurrence(Base):
    """One detection of a finding in a run, with its evidence, already masked and truncated by
    the scanner before insert (RF-66, RF-67, RN-11)."""

    __tablename__ = "finding_occurrences"
    __table_args__ = (
        ForeignKeyConstraint(["project_id", "finding_id"], ["findings.project_id", "findings.id"]),
        ForeignKeyConstraint(["project_id", "run_id"], ["runs.project_id", "runs.id"]),
        CheckConstraint(one_of("severity", Severity), name="severity"),
        CheckConstraint(
            f"octet_length(evidence::text) <= {MAX_EVIDENCE_BYTES}", name="evidence_size"
        ),
        Index(None, "project_id", "run_id"),
    )

    finding_id: Mapped[UUID] = mapped_column(primary_key=True)
    run_id: Mapped[UUID] = mapped_column(primary_key=True)
    project_id: Mapped[UUID] = project_fk()
    severity: Mapped[str]
    explanation: Mapped[str]
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB)
    detected_at: Mapped[datetime] = created_at()


class FindingEvent(Base):
    """Each status change of a finding (RF-72). Insert-only."""

    __tablename__ = "finding_events"
    __table_args__ = (
        ForeignKeyConstraint(["project_id", "finding_id"], ["findings.project_id", "findings.id"]),
        ForeignKeyConstraint(["project_id", "run_id"], ["runs.project_id", "runs.id"]),
        CheckConstraint(one_of("from_status", FindingStatus), name="from_status"),
        CheckConstraint(one_of("to_status", FindingStatus), name="to_status"),
        CheckConstraint(one_of("reason", FindingEventReason), name="reason"),
        # Caused either by a run (automatic) or by the analyst (accept, revert, delete...).
        CheckConstraint("(run_id IS NULL) <> (user_id IS NULL)", name="single_cause"),
        Index(None, "project_id", "finding_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    project_id: Mapped[UUID] = project_fk()
    finding_id: Mapped[UUID]
    from_status: Mapped[str | None]
    to_status: Mapped[str]
    reason: Mapped[str]
    run_id: Mapped[UUID | None]
    user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    justification: Mapped[str | None]
    occurred_at: Mapped[datetime] = created_at()
