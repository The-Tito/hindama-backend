"""Audit log and anonymous metrics (modelo.md, section 3.5; ADR-015).

None of these tables has a foreign key on purpose: they must survive the deletion of the users and
projects they mention. Metrics have no user, project, host or operation at all.
"""

import datetime as dt
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, CheckConstraint, Identity, Index, LargeBinary, SmallInteger, text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from hindama.models.base import Base, created_at, one_of, uuid_pk
from hindama.models.enums import DailyMetricName, Module, Severity


class AuditLogEntry(Base):
    """Sensitive actions (F-14). Immutable: see the security migration (RF-83, RF-90)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint("(host_hmac IS NULL) = (hmac_version IS NULL)", name="hmac_versioned"),
        Index(None, "occurred_at"),
        Index(None, "user_id", "occurred_at"),
        Index(None, "action", "occurred_at"),
        Index(None, "host_hmac"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    occurred_at: Mapped[dt.datetime] = created_at()
    user_id: Mapped[UUID | None]  # opaque: no foreign key
    action: Mapped[str]
    project_id: Mapped[UUID | None]  # opaque: no foreign key
    host_hmac: Mapped[bytes | None] = mapped_column(LargeBinary)  # HMAC-SHA256, never the host
    hmac_version: Mapped[int | None] = mapped_column(SmallInteger)
    source_ip: Mapped[str | None] = mapped_column(INET)
    # Modules, limits, block reason... never credentials, justifications or analyst free text.
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))


class FindingMetric(Base):
    """One anonymous fact per finding, written when the finding is created (RF-89)."""

    __tablename__ = "finding_metrics"
    __table_args__ = (
        CheckConstraint("extract(isodow FROM week) = 1", name="week_starts_monday"),
        CheckConstraint(one_of("module", Module), name="module"),
        CheckConstraint(one_of("severity", Severity), name="severity"),
        CheckConstraint("days_to_resolve >= 0", name="days_to_resolve"),
        CheckConstraint("regressions >= 0", name="regressions"),
        Index(None, "week"),
    )

    id: Mapped[UUID] = uuid_pk()
    week: Mapped[dt.date]  # Monday of the detection week, not the exact date
    module: Mapped[str]
    owasp_category: Mapped[str]
    cwe: Mapped[str | None]
    severity: Mapped[str]
    days_to_resolve: Mapped[int | None]
    regressions: Mapped[int] = mapped_column(default=0, server_default=text("0"))


class DailyMetric(Base):
    """Aggregated counters per day (RF-78, RF-89)."""

    __tablename__ = "daily_metrics"
    __table_args__ = (
        CheckConstraint(one_of("metric", DailyMetricName), name="metric"),
        CheckConstraint("value >= 0", name="value"),
    )

    date: Mapped[dt.date] = mapped_column(primary_key=True)
    metric: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[int] = mapped_column(BigInteger, default=0, server_default=text("0"))
