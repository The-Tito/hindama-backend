"""Runs and what they evaluate (modelo.md, section 3.3)."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKeyConstraint,
    Identity,
    Index,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from hindama.models.base import Base, created_at, one_of, uuid_pk
from hindama.models.enums import (
    ACTIVE_RUN_STATUSES,
    END_REASONS_BY_STATUS,
    CreatedResourceStatus,
    EndReason,
    Module,
    RunStatus,
    Verdict,
)
from hindama.models.projects import project_fk


def _end_reason_matches_status() -> str:
    active = f"({one_of('status', ACTIVE_RUN_STATUSES)} AND end_reason IS NULL)"
    finals = [
        # IS NOT NULL first: `NULL IN (...)` is NULL, and a CHECK that evaluates to NULL passes.
        f"(status = '{status}' AND end_reason IS NOT NULL AND {one_of('end_reason', reasons)})"
        for status, reasons in END_REASONS_BY_STATUS.items()
    ]
    return " OR ".join([active, *finals])


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (
        UniqueConstraint("project_id", "id"),
        UniqueConstraint("project_id", "number"),
        ForeignKeyConstraint(
            ["project_id", "contract_version_id"],
            ["contract_versions.project_id", "contract_versions.id"],
        ),
        ForeignKeyConstraint(["project_id", "source_run_id"], ["runs.project_id", "runs.id"]),
        CheckConstraint("number >= 1", name="number_positive"),
        CheckConstraint(one_of("status", RunStatus), name="status"),
        CheckConstraint(one_of("end_reason", EndReason), name="end_reason"),
        CheckConstraint(_end_reason_matches_status(), name="end_reason_matches_status"),
        CheckConstraint(
            f"({one_of('status', ACTIVE_RUN_STATUSES)}) = (finished_at IS NULL)",
            name="finished_at_when_final",
        ),
        CheckConstraint("requests_sent >= 0", name="requests_sent"),
        # One active run per project (RN-07, RF-53).
        Index(
            "uq_runs_one_active",
            "project_id",
            unique=True,
            postgresql_where=text(one_of("status", ACTIVE_RUN_STATUSES)),
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    project_id: Mapped[UUID] = project_fk()
    number: Mapped[int]
    contract_version_id: Mapped[UUID | None]
    source_run_id: Mapped[UUID | None]  # set when it repeats a previous run (RF-71)
    status: Mapped[str] = mapped_column(default=RunStatus.QUEUED, server_default=RunStatus.QUEUED)
    end_reason: Mapped[str | None]
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)  # modules, limits, risk confirmations
    created_at: Mapped[datetime] = created_at()
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    heartbeat_at: Mapped[datetime | None]
    job_id: Mapped[str | None]
    requests_sent: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    current_module: Mapped[str | None]


class Result(Base):
    """An evaluated cell (run, module, operation, identity): the access matrix (RF-64) and the
    record of what was evaluated, used to resolve findings (ADR-014). Written only once the cell
    is complete, so a cancelled half-cell leaves no row."""

    __tablename__ = "results"
    __table_args__ = (
        ForeignKeyConstraint(["project_id", "run_id"], ["runs.project_id", "runs.id"]),
        ForeignKeyConstraint(
            ["project_id", "operation_id"], ["operations.project_id", "operations.id"]
        ),
        ForeignKeyConstraint(
            ["project_id", "identity_id"], ["identities.project_id", "identities.id"]
        ),
        CheckConstraint(one_of("module", Module), name="module"),
        CheckConstraint(one_of("verdict", Verdict), name="verdict"),
        # operation_id is NULL for API-wide checks (e.g. CORS); NULLs must still collide.
        UniqueConstraint(
            "run_id", "module", "operation_id", "identity_id", postgresql_nulls_not_distinct=True
        ),
        Index(None, "project_id", "module", "operation_id", "identity_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    project_id: Mapped[UUID] = project_fk()
    run_id: Mapped[UUID]
    module: Mapped[str]
    operation_id: Mapped[UUID | None]
    # Always an identity: API-wide and unauthenticated checks use the anonymous one (RF-34).
    identity_id: Mapped[UUID]
    expected: Mapped[str]
    observed: Mapped[str]
    verdict: Mapped[str]
    evaluated_at: Mapped[datetime] = created_at()


class CreatedResource(Base):
    """What the platform created in the analyst's API and must delete (RN-06). Written before the
    resource is created, so it can be cleaned up even if the process dies (CU-23)."""

    __tablename__ = "created_resources"
    __table_args__ = (
        ForeignKeyConstraint(["project_id", "run_id"], ["runs.project_id", "runs.id"]),
        ForeignKeyConstraint(
            ["project_id", "operation_id"], ["operations.project_id", "operations.id"]
        ),
        CheckConstraint(one_of("status", CreatedResourceStatus), name="status"),
        CheckConstraint("attempts BETWEEN 0 AND 3", name="attempts"),
        Index(
            "ix_created_resources_pending",
            "run_id",
            postgresql_where=text("status = 'pending'"),
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    project_id: Mapped[UUID] = project_fk()
    run_id: Mapped[UUID]
    operation_id: Mapped[UUID]
    location: Mapped[str]  # path to delete it; never credentials
    status: Mapped[str] = mapped_column(
        default=CreatedResourceStatus.PENDING, server_default=CreatedResourceStatus.PENDING
    )
    attempts: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    last_error: Mapped[str | None]
    created_at: Mapped[datetime] = created_at()
