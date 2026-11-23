"""`users`: the platform account of a Cognito user (modelo.md 3.1)."""

from uuid import UUID

from sqlalchemy import delete, exists, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import Project, Run, User
from hindama.models.base import new_id
from hindama.models.enums import ACTIVE_RUN_STATUSES


async def find_id(session: AsyncSession, cognito_sub: str) -> UUID | None:
    return await session.scalar(select(User.id).where(User.cognito_sub == cognito_sub))


async def create(session: AsyncSession, cognito_sub: str) -> UUID | None:
    """Inserts the user and returns its id, or None if a concurrent request already did.

    ON CONFLICT DO NOTHING makes the first access safe under concurrency (arquitectura 4.1).
    """
    statement = (
        insert(User)
        .values(id=new_id(), cognito_sub=cognito_sub)
        .on_conflict_do_nothing(index_elements=[User.cognito_sub])
        .returning(User.id)
    )
    return await session.scalar(statement)


async def get(session: AsyncSession, user_id: UUID) -> User:
    """The caller's own row; RLS hides every other one."""
    return await session.get_one(User, user_id)


async def accept_terms(session: AsyncSession, user_id: UUID, version: str) -> User:
    """Records the accepted version with the database clock (RF-16)."""
    statement = (
        update(User)
        .where(User.id == user_id)
        .values(terms_version=version, terms_accepted_at=func.now())
        .returning(User)
        .execution_options(populate_existing=True)
    )
    user = await session.scalar(statement)
    if user is None:  # pragma: no cover - the caller's row exists (resolve_user)
        raise RuntimeError("user row not found")
    return user


async def has_active_run(session: AsyncSession, user_id: UUID) -> bool:
    """Whether any project of the user has a queued or running run (CU-25 E1)."""
    statement = select(
        exists().where(
            Project.owner_id == user_id,
            Run.project_id == Project.id,
            Run.status.in_(ACTIVE_RUN_STATUSES),
        )
    )
    return bool(await session.scalar(statement))


async def delete_user(session: AsyncSession, user_id: UUID) -> None:
    """Deletes the user; its projects and all their content go with it (ON DELETE CASCADE)."""
    await session.execute(delete(User).where(User.id == user_id))
