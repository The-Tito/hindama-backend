"""Resources of a project: objects of the analyst's API and their owner identity (modelo.md 3.3;
RF-35 to RF-38). Runs as `hindama_api` with Row-Level Security (RN-02)."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import Resource


async def page(
    session: AsyncSession,
    project_id: UUID,
    *,
    identity_id: UUID | None,
    resource_type: str | None,
    page: int,
    page_size: int,
) -> tuple[list[Resource], int]:
    """By type, then identifier (contract, `listResources`)."""
    where = [Resource.project_id == project_id]
    if identity_id is not None:
        where.append(Resource.identity_id == identity_id)
    if resource_type is not None:
        where.append(Resource.resource_type == resource_type)
    total = await session.scalar(select(func.count()).select_from(Resource).where(*where))
    statement = (
        select(Resource)
        .where(*where)
        .order_by(Resource.resource_type, Resource.value, Resource.id)
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    return list(await session.scalars(statement)), total or 0


async def get(
    session: AsyncSession, project_id: UUID, resource_id: UUID, *, for_update: bool = False
) -> Resource | None:
    statement = select(Resource).where(
        Resource.project_id == project_id, Resource.id == resource_id
    )
    if for_update:
        statement = statement.with_for_update()
    resource: Resource | None = await session.scalar(statement)
    return resource


async def owner_of(
    session: AsyncSession, project_id: UUID, resource_type: str, value: str
) -> Resource | None:
    """The resource with this type and identifier: an object has a single owner."""
    resource: Resource | None = await session.scalar(
        select(Resource).where(
            Resource.project_id == project_id,
            Resource.resource_type == resource_type,
            Resource.value == value,
        )
    )
    return resource
