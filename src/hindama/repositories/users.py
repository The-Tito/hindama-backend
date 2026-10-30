"""`users`: the platform account of a Cognito user (modelo.md 3.1)."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import User
from hindama.models.base import new_id


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
