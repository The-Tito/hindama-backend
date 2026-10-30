"""Service health."""

import structlog
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.db.session import ping

log = structlog.get_logger(__name__)


async def is_database_up(engine: AsyncEngine) -> bool:
    try:
        await ping(engine)
    except Exception as exc:
        # Only the exception type: its message may include the host or user of the database.
        log.warning("database_unavailable", error=type(exc).__name__)
        return False
    return True
