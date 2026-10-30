"""Platform accounts (F-01)."""

from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.auth import CurrentUser, Principal
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
