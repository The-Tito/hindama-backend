"""Anonymous metrics (modelo.md 7.3): written in the same transaction as the fact they count."""

from datetime import UTC, datetime

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import DailyMetric
from hindama.models.enums import DailyMetricName


async def increment_daily(session: AsyncSession, metric: DailyMetricName) -> None:
    statement = insert(DailyMetric).values(date=datetime.now(UTC).date(), metric=metric, value=1)
    await session.execute(
        statement.on_conflict_do_update(
            index_elements=[DailyMetric.date, DailyMetric.metric],
            set_={"value": DailyMetric.value + 1},
        )
    )
