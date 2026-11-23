"""Resources of a project: objects of the analyst's API and their owner identity (modelo.md 3.3;
RF-35 to RF-38). Runs as `hindama_api` with Row-Level Security (RN-02)."""

from collections.abc import Iterable
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import Identity, Operation, OperationVersion, Resource
from hindama.models.enums import AuthType, HttpMethod
from hindama.repositories.identities import latest_description


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


async def owners(
    session: AsyncSession, project_id: UUID, resource_types: Iterable[str]
) -> dict[tuple[str, str], UUID]:
    """Who owns each object of these types: `(type, identifier)` → identity."""
    types = sorted(set(resource_types))
    if not types:
        return {}
    statement = select(Resource.resource_type, Resource.value, Resource.identity_id).where(
        Resource.project_id == project_id, Resource.resource_type.in_(types)
    )
    return {(row[0], row[1]): row[2] for row in await session.execute(statement)}


async def searchers(session: AsyncSession, project_id: UUID) -> list[Identity]:
    """Live identities with a credential, by creation: the ones that discover (RF-36)."""
    statement = (
        select(Identity)
        .where(
            Identity.project_id == project_id,
            Identity.deleted_at.is_(None),
            Identity.auth_type != AuthType.NONE,
        )
        .order_by(Identity.created_at, Identity.id)
    )
    return list(await session.scalars(statement))


async def get_operations_without_parameters(
    session: AsyncSession, project_id: UUID
) -> list[tuple[Operation, OperationVersion, UUID]]:
    """Current GET operations without path parameters, each with its newest description and the
    contract version it comes from, by path: the candidates to list resources (RF-36)."""
    operations = await session.scalars(
        select(Operation)
        .where(
            Operation.project_id == project_id,
            Operation.retired_at.is_(None),
            Operation.method == HttpMethod.GET,
            ~Operation.normalized_path.contains("{"),
        )
        .order_by(Operation.path, Operation.id)
    )
    result = []
    for operation in list(operations):
        described = await latest_description(session, project_id, operation.id)
        if described is not None:
            result.append((operation, described[0], described[1]))
    return result
