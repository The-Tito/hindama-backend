"""Anonymous metrics (modelo.md 7.3): written in the same transaction as the fact they count."""

from dataclasses import dataclass
from datetime import UTC, date, datetime

from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import DailyMetric, FindingMetric
from hindama.models.enums import DailyMetricName


async def increment_daily(session: AsyncSession, metric: DailyMetricName) -> None:
    statement = insert(DailyMetric).values(date=datetime.now(UTC).date(), metric=metric, value=1)
    await session.execute(
        statement.on_conflict_do_update(
            index_elements=[DailyMetric.date, DailyMetric.metric],
            set_={"value": DailyMetric.value + 1},
        )
    )


# ------------------------------------------------------------------ reads (CU-20)


@dataclass(frozen=True, slots=True)
class FindingGroup:
    """Findings that share week, module, OWASP category and severity, with their resolution."""

    week: date
    module: str
    owasp_category: str
    severity: str
    detected: int
    regressions: int
    resolved: int
    days_to_resolve: int  # sum over the resolved ones


async def daily_values(
    session: AsyncSession, date_from: date, date_to: date
) -> dict[tuple[date, str], int]:
    """`(date, metric) → value` of the period, both ends included."""
    rows = await session.execute(
        select(DailyMetric.date, DailyMetric.metric, DailyMetric.value).where(
            DailyMetric.date.between(date_from, date_to)
        )
    )
    return {(day, metric): value for day, metric, value in rows}


async def users_at(session: AsyncSession, day: date) -> int:
    """Accounts at the end of `day`: sign-ups minus deletions since the platform started."""
    signed = case((DailyMetric.metric == DailyMetricName.DELETED_ACCOUNTS, -1), else_=1)
    total = await session.scalar(
        select(func.coalesce(func.sum(DailyMetric.value * signed), 0)).where(
            DailyMetric.date <= day,
            DailyMetric.metric.in_([DailyMetricName.NEW_USERS, DailyMetricName.DELETED_ACCOUNTS]),
        )
    )
    return max(int(total or 0), 0)


async def finding_groups(
    session: AsyncSession, week_from: date, week_to: date
) -> list[FindingGroup]:
    """The findings first detected in the weeks whose Monday is in `[week_from, week_to]`."""
    rows = await session.execute(
        select(
            FindingMetric.week,
            FindingMetric.module,
            FindingMetric.owasp_category,
            FindingMetric.severity,
            func.count(),
            func.coalesce(func.sum(FindingMetric.regressions), 0),
            func.count(FindingMetric.days_to_resolve),
            func.coalesce(func.sum(FindingMetric.days_to_resolve), 0),
        )
        .where(FindingMetric.week.between(week_from, week_to))
        .group_by(
            FindingMetric.week,
            FindingMetric.module,
            FindingMetric.owasp_category,
            FindingMetric.severity,
        )
    )
    return [
        FindingGroup(week, module, category, severity, detected, regressions, resolved, days or 0)
        for week, module, category, severity, detected, regressions, resolved, days in rows
    ]
