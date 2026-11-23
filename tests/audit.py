"""Reading the audit log as the schema owner, which RLS does not filter (tests only)."""

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import AuditLogEntry


async def audit_entries(
    owner: AsyncEngine, *, project_id: str | UUID | None = None, user_id: str | UUID | None = None
) -> list[AuditLogEntry]:
    """Entries of one project or one user, oldest first."""
    statement = select(AuditLogEntry).order_by(AuditLogEntry.id)
    if project_id is not None:
        statement = statement.where(AuditLogEntry.project_id == UUID(str(project_id)))
    if user_id is not None:
        statement = statement.where(AuditLogEntry.user_id == UUID(str(user_id)))
    async with AsyncSession(owner) as session:
        return list((await session.scalars(statement)).all())


def actions(entries: list[AuditLogEntry]) -> list[str]:
    return [entry.action for entry in entries]


def details_of(entries: list[AuditLogEntry], action: str) -> list[dict[str, Any]]:
    return [entry.details for entry in entries if entry.action == action]
