"""FastAPI dependencies shared by the routers."""

from collections.abc import AsyncIterator
from typing import Annotated

import structlog
from fastapi import Depends, Request
from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from hindama.core.auth import CurrentUser, Principal, Role
from hindama.core.errors import ForbiddenError, ServiceUnavailableError
from hindama.db.session import set_rls_context
from hindama.services.accounts import resolve_user

log = structlog.get_logger(__name__)

# Raised when the connection cannot be opened: the database is down, starting or unreachable.
DATABASE_UNAVAILABLE = (OSError, TimeoutError, OperationalError, InterfaceError)


def get_engine(request: Request) -> AsyncEngine:
    engine: AsyncEngine = request.app.state.engine
    return engine


async def open_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """One transaction per request, with the caller fixed for Row-Level Security (ADR-013).

    Commits when the endpoint returns and rolls back if it raises. Declared with scope="function"
    so the commit happens before the response is sent: a 2xx always means the data is saved.
    """
    principal: Principal = request.state.principal  # set by AuthenticationMiddleware
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with session_factory() as session, session.begin():
        try:
            await set_rls_context(session, cognito_sub=principal.cognito_sub, role=principal.role)
            user = await resolve_user(session, principal)
            await set_rls_context(
                session, cognito_sub=user.cognito_sub, role=user.role, user_id=user.id
            )
        except DATABASE_UNAVAILABLE as error:
            # Only the type: the message may include the host or user of the database.
            log.warning("database_unavailable", error=type(error).__name__)
            raise ServiceUnavailableError() from error
        request.state.user = user
        yield session


DbSession = Annotated[AsyncSession, Depends(open_db_session, scope="function")]


def get_current_user(request: Request, _: DbSession) -> CurrentUser:
    user: CurrentUser = request.state.user
    return user


AnyUser = Annotated[CurrentUser, Depends(get_current_user)]


def require_analyst(user: AnyUser) -> CurrentUser:
    """Project endpoints: the administrator never reaches project content (RN-03, RF-80)."""
    if user.role is not Role.ANALYST:
        raise ForbiddenError(
            "role.forbidden",
            "Acción no permitida",
            "Tu rol no permite acceder a esta sección.",
        )
    return user


def require_admin(user: AnyUser) -> CurrentUser:
    """`/admin/*` endpoints (F-13, F-14)."""
    if user.role is not Role.ADMIN:
        raise ForbiddenError(
            "role.forbidden",
            "Acción no permitida",
            "Tu rol no permite acceder a esta sección.",
        )
    return user


Analyst = Annotated[CurrentUser, Depends(require_analyst)]
Admin = Annotated[CurrentUser, Depends(require_admin)]
