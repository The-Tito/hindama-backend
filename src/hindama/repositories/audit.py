"""`audit_log` (F-14; RF-81 to RF-84; modelo.md 3.5 and 7.4).

Both database roles may only INSERT the columns without `id` and `occurred_at` (nobody dates an
entry inside the purge window), and only the administrator's session may SELECT (RLS on
`app.role`). So the insert never uses RETURNING, and nothing here updates or deletes: a trigger
rejects both (RF-83).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, insert, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.audit import HostDigest
from hindama.models import AuditLogEntry, Project
from hindama.models.enums import AuditAction


@dataclass(frozen=True, slots=True)
class NewEntry:
    action: AuditAction
    user_id: UUID | None
    project_id: UUID | None = None
    host: HostDigest | None = None
    source_ip: str | None = None
    details: dict[str, Any] | None = None


async def project_host(session: AsyncSession, project_id: UUID) -> str | None:
    """The host of one of the caller's projects (RLS), to keep its HMAC."""
    host: str | None = await session.scalar(select(Project.host).where(Project.id == project_id))
    return host


async def add(session: AsyncSession, entry: NewEntry) -> None:
    # `inline`: no RETURNING id nor nextval() first. Neither role may read the table or its
    # sequence, and nobody needs the new id back.
    await session.execute(
        insert(AuditLogEntry)
        .inline()
        .values(
            action=entry.action.value,
            user_id=entry.user_id,
            project_id=entry.project_id,
            host_hmac=None if entry.host is None else entry.host.value,
            hmac_version=None if entry.host is None else entry.host.version,
            source_ip=entry.source_ip,
            details=entry.details or {},
        )
    )


@dataclass(frozen=True, slots=True)
class Filters:
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None
    actions: tuple[AuditAction, ...] = ()
    user_id: UUID | None = None
    hosts: tuple[HostDigest, ...] | None = None  # None: no host filter


async def list_page(
    session: AsyncSession, filters: Filters, page: int, page_size: int
) -> tuple[list[AuditLogEntry], int]:
    conditions = []
    if filters.occurred_from is not None:
        conditions.append(AuditLogEntry.occurred_at >= filters.occurred_from)
    if filters.occurred_to is not None:
        conditions.append(AuditLogEntry.occurred_at < filters.occurred_to)
    if filters.actions:
        conditions.append(AuditLogEntry.action.in_([a.value for a in filters.actions]))
    if filters.user_id is not None:
        conditions.append(AuditLogEntry.user_id == filters.user_id)
    if filters.hosts is not None:
        conditions.append(
            or_(
                *(
                    and_(
                        AuditLogEntry.host_hmac == digest.value,
                        AuditLogEntry.hmac_version == digest.version,
                    )
                    for digest in filters.hosts
                )
            )
        )
    total = (
        await session.scalar(select(func.count()).select_from(AuditLogEntry).where(*conditions))
        or 0
    )
    statement = (
        select(AuditLogEntry)
        .where(*conditions)
        .order_by(AuditLogEntry.occurred_at.desc(), AuditLogEntry.id.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    return list((await session.scalars(statement)).all()), total
