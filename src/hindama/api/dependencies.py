"""FastAPI dependencies shared by the routers."""

from collections.abc import AsyncIterator
from typing import Annotated

import structlog
from fastapi import Depends, Request
from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from hindama.core.audit import HostHasher, client_ip
from hindama.core.auth import CurrentUser, Principal, Role
from hindama.core.cognito import Profile, ProfileClient
from hindama.core.errors import ForbiddenError, ServiceUnavailableError
from hindama.db.session import set_rls_context
from hindama.services.accounts import resolve_user
from hindama.services.audit import Auditor

log = structlog.get_logger(__name__)

# Raised when the connection cannot be opened: the database is down, starting or unreachable.
DATABASE_UNAVAILABLE = (OSError, TimeoutError, OperationalError, InterfaceError)

CLIENT_IP_HEADER = "X-Hindama-Client-IP"


def source_ip(request: Request) -> str | None:
    """The browser's IP for the audit log (RF-82), as the frontend reported it, if valid.

    Only the frontend reaches the API (SG-FE, behind Caddy), so the browser cannot send it
    directly; it is recorded, never used to authorize (convenciones.md, section 3)."""
    return client_ip(request.headers.get(CLIENT_IP_HEADER))


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
            user = await resolve_user(session, principal, source_ip(request))
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


def access_token(request: Request) -> str:
    """The caller's token, already validated by the middleware."""
    _, _, token = request.headers["authorization"].partition(" ")
    return token.strip()


def get_profile_client(request: Request) -> ProfileClient:
    client: ProfileClient = request.app.state.profiles
    return client


async def get_profile(request: Request) -> Profile:
    """Name, email and TOTP status from Cognito, with the token the middleware validated."""
    return await get_profile_client(request).get(access_token(request))


CallerProfile = Annotated[Profile, Depends(get_profile)]


async def require_admin(request: Request, user: AnyUser) -> CurrentUser:
    """`/admin/*` endpoints (F-13, F-14), only with the TOTP active (RF-86, ADR-018).

    Access tokens do not say whether the sign-in used the second factor; with the TOTP active,
    Cognito asks for it at every sign-in, so its status (`GetUser`) is what the API checks. The
    role goes first: an analyst gets its 403 without a call to Cognito.
    """
    if user.role is not Role.ADMIN:
        raise ForbiddenError(
            "role.forbidden",
            "Acción no permitida",
            "Tu rol no permite acceder a esta sección.",
        )
    if not (await get_profile(request)).mfa_enabled:
        raise ForbiddenError(
            "auth.mfa_required",
            "Segundo factor obligatorio",
            "Activa el segundo factor en tu perfil para entrar al panel de administración.",
        )
    return user


Analyst = Annotated[CurrentUser, Depends(require_analyst)]
Admin = Annotated[CurrentUser, Depends(require_admin)]


def get_hasher(request: Request) -> HostHasher:
    hasher: HostHasher = request.app.state.host_hasher
    return hasher


Hasher = Annotated[HostHasher, Depends(get_hasher)]


def get_auditor(request: Request, db: DbSession, user: AnyUser, hasher: Hasher) -> Auditor:
    """The audit log of this request (RF-81, RF-82): its transaction, user and browser IP."""
    return Auditor(
        session=db,
        session_factory=request.app.state.session_factory,
        hasher=hasher,
        user_id=user.id,
        source_ip=source_ip(request),
    )


Audit = Annotated[Auditor, Depends(get_auditor)]
