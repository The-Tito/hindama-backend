"""Contract versions and operations (modelo.md 3.2; RF-24, RF-26).

As every repository of project data, it runs as `hindama_api` with Row-Level Security: another
analyst's rows are invisible (RN-02). The stored document (up to 5 MB) is never loaded unless asked.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from hindama.models import ContractVersion, Operation, OperationVersion


def _versions() -> Any:
    return select(ContractVersion).options(defer(ContractVersion.document))


async def latest(session: AsyncSession, project_id: UUID) -> ContractVersion | None:
    statement = (
        _versions()
        .where(ContractVersion.project_id == project_id)
        .order_by(ContractVersion.number.desc())
        .limit(1)
    )
    version: ContractVersion | None = await session.scalar(statement)
    return version


async def get_version(
    session: AsyncSession, project_id: UUID, contract_id: UUID
) -> ContractVersion | None:
    statement = _versions().where(
        ContractVersion.project_id == project_id, ContractVersion.id == contract_id
    )
    version: ContractVersion | None = await session.scalar(statement)
    return version


async def version_by_number(
    session: AsyncSession, project_id: UUID, number: int
) -> ContractVersion | None:
    statement = _versions().where(
        ContractVersion.project_id == project_id, ContractVersion.number == number
    )
    version: ContractVersion | None = await session.scalar(statement)
    return version


async def list_versions(
    session: AsyncSession, project_id: UUID, page: int, page_size: int
) -> tuple[list[ContractVersion], int]:
    where = ContractVersion.project_id == project_id
    total = await session.scalar(select(func.count()).select_from(ContractVersion).where(where))
    statement = (
        _versions()
        .where(where)
        .order_by(ContractVersion.number.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    return list(await session.scalars(statement)), total or 0


async def operations_by_key(
    session: AsyncSession, project_id: UUID
) -> dict[tuple[str, str], Operation]:
    """Every operation of the project, retired ones included, by (method, normalized path)."""
    statement = select(Operation).where(Operation.project_id == project_id)
    return {(op.method, op.normalized_path): op for op in await session.scalars(statement)}


@dataclass(frozen=True, slots=True)
class VersionedOperation:
    """An operation as one contract version describes it: what RF-26 compares."""

    operation_id: UUID
    method: str
    path: str
    detail: tuple[Any, ...]  # everything whose change makes the operation "modified"


async def operations_of_version(
    session: AsyncSession, version_id: UUID
) -> dict[UUID, VersionedOperation]:
    statement = (
        select(OperationVersion, Operation.method)
        .join(
            Operation,
            (Operation.project_id == OperationVersion.project_id)
            & (Operation.id == OperationVersion.operation_id),
        )
        .where(OperationVersion.contract_version_id == version_id)
    )
    result = {}
    for row, method in await session.execute(statement):
        result[row.operation_id] = VersionedOperation(
            operation_id=row.operation_id,
            method=method,
            path=row.path,
            detail=(
                row.path,
                row.parameters,
                row.request_body,
                row.security,
                row.schemas,
            ),
        )
    return result


async def list_operations(
    session: AsyncSession,
    project_id: UUID,
    *,
    include_retired: bool,
    method: str | None,
    page: int,
    page_size: int,
) -> tuple[list[tuple[Operation, OperationVersion]], int]:
    """A page of operations, ordered by path and method, each with its latest description (the
    current version, or the last one that included it if it was retired)."""
    conditions = [Operation.project_id == project_id]
    if not include_retired:
        conditions.append(Operation.retired_at.is_(None))
    if method is not None:
        conditions.append(Operation.method == method)
    total = await session.scalar(select(func.count()).select_from(Operation).where(*conditions))
    statement = (
        select(Operation)
        .where(*conditions)
        .order_by(Operation.path, Operation.method, Operation.id)
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    operations = list(await session.scalars(statement))
    if not operations:
        return [], total or 0
    latest_versions = (
        select(OperationVersion)
        .join(
            ContractVersion,
            (ContractVersion.project_id == OperationVersion.project_id)
            & (ContractVersion.id == OperationVersion.contract_version_id),
        )
        .where(
            OperationVersion.project_id == project_id,
            OperationVersion.operation_id.in_([op.id for op in operations]),
        )
        .order_by(OperationVersion.operation_id, ContractVersion.number.desc())
        .ext(distinct_on(OperationVersion.operation_id))
    )
    described = {row.operation_id: row for row in await session.scalars(latest_versions)}
    return [(op, described[op.id]) for op in operations], total or 0
