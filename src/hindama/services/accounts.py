"""Platform accounts (F-01)."""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.auth import CurrentUser, Principal
from hindama.core.cognito import Profile
from hindama.core.errors import UnprocessableError
from hindama.models import User
from hindama.models.enums import DailyMetricName
from hindama.repositories import metrics, users


async def resolve_user(session: AsyncSession, principal: Principal) -> CurrentUser:
    """Finds the user of the token, registering it on its first access (arquitectura 4.1).

    Needs `app.cognito_sub` already set: the `users` policy only shows the caller's own row.
    """
    user_id = await users.find_id(session, principal.cognito_sub)
    if user_id is None:
        user_id = await users.create(session, principal.cognito_sub)
        if user_id is not None:
            await metrics.increment_daily(session, DailyMetricName.NEW_USERS)
        else:  # a concurrent request registered it first
            user_id = await users.find_id(session, principal.cognito_sub)
    if user_id is None:  # pragma: no cover - the row exists after ON CONFLICT
        raise RuntimeError("user row not found after registration")
    return CurrentUser(id=user_id, cognito_sub=principal.cognito_sub, role=principal.role)


@dataclass(frozen=True, slots=True)
class Terms:
    current_version: str
    accepted_version: str | None
    accepted_at: datetime | None

    @property
    def acceptance_required(self) -> bool:
        """Accepting an older version does not count: a new version asks again (RN-12)."""
        return self.accepted_version != self.current_version


@dataclass(frozen=True, slots=True)
class Account:
    user: CurrentUser
    profile: Profile
    terms: Terms


def _account(user: CurrentUser, profile: Profile, row: User, current_version: str) -> Account:
    terms = Terms(current_version, row.terms_version, row.terms_accepted_at)
    return Account(user=user, profile=profile, terms=terms)


async def get_account(
    session: AsyncSession, user: CurrentUser, profile: Profile, current_version: str
) -> Account:
    row = await users.get(session, user.id)
    return _account(user, profile, row, current_version)


async def accept_terms(
    session: AsyncSession,
    user: CurrentUser,
    profile: Profile,
    version: str,
    current_version: str,
) -> Account:
    """RF-16, RN-12. Accepting the version already accepted changes nothing (keeps its date)."""
    if version != current_version:
        raise UnprocessableError(
            "terms.outdated_version",
            "Términos desactualizados",
            "La versión de los términos no es la vigente. Vuelve a leerlos y acéptalos.",
        )
    row = await users.get(session, user.id)
    if row.terms_version != version:
        row = await users.accept_terms(session, user.id, version)
    return _account(user, profile, row, current_version)
