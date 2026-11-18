"""Identities of a project (modelo.md 3.3; RF-28 to RF-34).

Runs as `hindama_api` with Row-Level Security: another analyst's identities are invisible (RN-02).
Deleted identities stay as rows (findings reference them) but no query here returns them.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import (
    ContractVersion,
    Finding,
    Identity,
    Operation,
    OperationVersion,
    Project,
    Resource,
)
from hindama.models.enums import (
    AuthType,
    HttpMethod,
    ResolutionReason,
)
from hindama.repositories import findings


@dataclass(frozen=True, slots=True)
class IdentityRow:
    identity: Identity
    login_operation: Operation | None
    resource_count: int


def _live(project_id: UUID) -> Any:
    return (Identity.project_id == project_id) & Identity.deleted_at.is_(None)


async def lock_project(session: AsyncSession, project_id: UUID) -> Project | None:
    """Serializes the identity changes of one project: the limit and the name stay exact."""
    project: Project | None = await session.scalar(
        select(Project).where(Project.id == project_id).with_for_update()
    )
    return project


async def count_live(session: AsyncSession, project_id: UUID) -> int:
    total = await session.scalar(
        select(func.count()).select_from(Identity).where(_live(project_id))
    )
    return total or 0


async def name_taken(
    session: AsyncSession, project_id: UUID, name: str, exclude: UUID | None = None
) -> bool:
    statement = select(Identity.id).where(_live(project_id), Identity.name == name)
    if exclude is not None:
        statement = statement.where(Identity.id != exclude)
    return await session.scalar(statement.limit(1)) is not None


async def get(
    session: AsyncSession, project_id: UUID, identity_id: UUID, *, for_update: bool = False
) -> Identity | None:
    statement = select(Identity).where(_live(project_id), Identity.id == identity_id)
    if for_update:
        statement = statement.with_for_update()
    identity: Identity | None = await session.scalar(statement)
    return identity


async def rows(
    session: AsyncSession,
    project_id: UUID,
    *,
    identity_id: UUID | None = None,
    page: int = 1,
    page_size: int = 1,
) -> tuple[list[IdentityRow], int]:
    """Live identities with their login operation and resource count. The anonymous one first,
    then by creation (contract, `listIdentities`)."""
    where = [_live(project_id)]
    if identity_id is not None:
        where.append(Identity.id == identity_id)
    total = await session.scalar(select(func.count()).select_from(Identity).where(*where))
    resources = (
        select(func.count())
        .select_from(Resource)
        .where(Resource.project_id == project_id, Resource.identity_id == Identity.id)
        .scalar_subquery()
    )
    statement = (
        select(Identity, Operation, resources)
        .outerjoin(
            Operation,
            (Operation.project_id == Identity.project_id)
            & (Operation.id == Identity.login_operation_id),
        )
        .where(*where)
        .order_by(
            case((Identity.auth_type == AuthType.NONE, 0), else_=1),
            Identity.created_at,
            Identity.id,
        )
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    result = [
        IdentityRow(identity=identity, login_operation=operation, resource_count=int(count))
        for identity, operation, count in await session.execute(statement)
    ]
    return result, total or 0


async def live_operation(
    session: AsyncSession, project_id: UUID, operation_id: UUID
) -> Operation | None:
    """An operation of the current contract (not retired)."""
    operation: Operation | None = await session.scalar(
        select(Operation).where(
            Operation.project_id == project_id,
            Operation.id == operation_id,
            Operation.retired_at.is_(None),
        )
    )
    return operation


async def latest_description(
    session: AsyncSession, project_id: UUID, operation_id: UUID
) -> tuple[OperationVersion, UUID] | None:
    """The newest description of an operation, and the contract version it comes from."""
    statement = (
        select(OperationVersion, ContractVersion.id)
        .join(
            ContractVersion,
            (ContractVersion.project_id == OperationVersion.project_id)
            & (ContractVersion.id == OperationVersion.contract_version_id),
        )
        .where(
            OperationVersion.project_id == project_id,
            OperationVersion.operation_id == operation_id,
        )
        .order_by(ContractVersion.number.desc())
        .limit(1)
    )
    row = (await session.execute(statement)).first()
    return None if row is None else (row[0], row[1])


async def contract_document(session: AsyncSession, version_id: UUID) -> bytes | None:
    document: bytes | None = await session.scalar(
        select(ContractVersion.document).where(ContractVersion.id == version_id)
    )
    return document


async def protected_get_operations(
    session: AsyncSession, project_id: UUID
) -> list[tuple[Operation, OperationVersion]]:
    """Current GET operations without path parameters, each with its newest description, by path
    length: the candidates to test a credential (RF-32)."""
    operations = list(
        await session.scalars(
            select(Operation)
            .where(
                Operation.project_id == project_id,
                Operation.retired_at.is_(None),
                Operation.method == HttpMethod.GET,
                ~Operation.normalized_path.contains("{"),
            )
            .order_by(func.length(Operation.path), Operation.path, Operation.id)
        )
    )
    result = []
    for operation in operations:
        described = await latest_description(session, project_id, operation.id)
        if described is not None and described[0].security:
            result.append((operation, described[0]))
    return result


async def soft_delete(session: AsyncSession, identity: Identity, user_id: UUID) -> None:
    """Section 7.1 of modelo.md, in the caller's transaction: the credential is erased at once,
    the name is freed, its resources go, and its open findings are resolved (`identity_deleted`)."""
    project_id = identity.project_id
    identity.encrypted_credential = None
    identity.key_version = None
    identity.credential_suffix = None
    identity.login_operation_id = None
    identity.deleted_at = func.now()
    await session.execute(
        delete(Resource).where(
            Resource.project_id == project_id, Resource.identity_id == identity.id
        )
    )
    await findings.close_open(
        session,
        project_id,
        Finding.identity_id == identity.id,
        ResolutionReason.IDENTITY_DELETED,
        user_id,
    )
    await session.flush()
