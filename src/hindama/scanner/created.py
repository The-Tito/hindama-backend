"""What is left in `created_resources` when a run ends (RN-06, CU-23 E1).

The module that creates a resource deletes it in the same cell, also when the run is cancelled
(scanner/modules/property_access.py). A row still `pending` when the run ends was not deleted:
it becomes `failed` with a reason, so the run shows it and the analyst can remove it by hand. The
scanner keeps no credential outside a live run, so it cannot delete it later.
"""

from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import CreatedResource
from hindama.models.enums import CreatedResourceStatus


async def give_up_pending(session: AsyncSession, run_id: UUID, reason: str) -> int:
    result = await session.execute(
        update(CreatedResource)
        .where(
            CreatedResource.run_id == run_id,
            CreatedResource.status == CreatedResourceStatus.PENDING,
        )
        .values(status=CreatedResourceStatus.FAILED, last_error=reason)
    )
    return int(result.rowcount or 0)  # type: ignore[attr-defined]
