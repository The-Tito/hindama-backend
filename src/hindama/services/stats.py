"""The administrator's statistics (CU-20; RF-78, RF-79, RF-89).

Only the anonymous metrics are read (`daily_metrics`, `finding_metrics`): never projects, findings
or users, so deleting a project or an account changes no figure (RF-89), and nothing in the answer
points to an analyst, a project or an API (RF-79).

Findings carry the Monday of their detection week, not a date (modelo.md, «Borrado y retención»):
a period takes the weeks whose Monday is between the Monday of `date_from` and `date_to`.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import date, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.errors import FieldIssue, UnprocessableError
from hindama.models.enums import DailyMetricName, Module, Severity
from hindama.repositories import metrics as repository
from hindama.schemas.admin import (
    AdminStats,
    AdminStatsActivity,
    AdminStatsFindings,
    AdminStatsPeriod,
    AdminStatsProjects,
    AdminStatsRuns,
    AdminStatsUsers,
    ModuleCount,
    OwaspCount,
    StatsGroup,
    WeekCount,
)
from hindama.schemas.projects import SeverityCount

DEFAULT_DAYS = 30
MAX_DAYS = 366


@dataclass(frozen=True, slots=True)
class Period:
    date_from: date
    date_to: date
    group: StatsGroup


def monday(day: date) -> date:
    return day - timedelta(days=day.weekday())


def period(date_from: date | None, date_to: date | None, group: StatsGroup, today: date) -> Period:
    """The defaults (the 30 days ending today) and the limits of the contract."""
    end = date_to or today
    default_span = timedelta(days=DEFAULT_DAYS - 1)
    # Near year 1 the subtraction would overflow: the period just starts there.
    start = date_from or (end - default_span if end - date.min >= default_span else date.min)
    if start > end:
        raise _invalid("date_to", "La fecha final no puede ser anterior a la inicial.")
    if (end - start).days + 1 > MAX_DAYS:
        raise _invalid("date_from", f"El periodo puede abarcar hasta {MAX_DAYS} días.")
    return Period(start, end, group)


def _invalid(field: str, message: str) -> UnprocessableError:
    return UnprocessableError(
        "validation.failed",
        "Periodo no válido",
        message,
        [FieldIssue(field, "validation.format", message)],
    )


def _buckets(chosen: Period) -> list[date]:
    if chosen.group == "day":
        days = (chosen.date_to - chosen.date_from).days + 1
        return [chosen.date_from + timedelta(days=n) for n in range(days)]
    return _weeks(chosen.date_from, chosen.date_to)


def _weeks(date_from: date, date_to: date) -> list[date]:
    first, last = monday(date_from), monday(date_to)
    return [first + timedelta(weeks=n) for n in range((last - first).days // 7 + 1)]


async def admin_stats(session: AsyncSession, chosen: Period) -> AdminStats:
    values = await repository.daily_values(session, chosen.date_from, chosen.date_to)
    per_bucket: dict[date, Counter[str]] = {start: Counter() for start in _buckets(chosen)}
    totals: Counter[str] = Counter()
    for (day, metric), value in values.items():
        start = day if chosen.group == "day" else monday(day)
        per_bucket[start][metric] += value
        totals[metric] += value

    return AdminStats(
        period=AdminStatsPeriod(
            date_from=chosen.date_from, date_to=chosen.date_to, group=chosen.group
        ),
        users=AdminStatsUsers(
            total=await repository.users_at(session, chosen.date_to),
            new=totals[DailyMetricName.NEW_USERS],
            deleted=totals[DailyMetricName.DELETED_ACCOUNTS],
        ),
        projects=AdminStatsProjects(created=totals[DailyMetricName.PROJECTS_CREATED]),
        runs=AdminStatsRuns(
            started=totals[DailyMetricName.RUNS_STARTED],
            cancelled=totals[DailyMetricName.RUNS_CANCELLED],
            failed=totals[DailyMetricName.RUNS_FAILED],
        ),
        activity=[
            AdminStatsActivity(
                start=start,
                **{metric.value: counts[metric] for metric in DailyMetricName},
            )
            for start, counts in per_bucket.items()
        ],
        findings=await _findings(session, chosen),
    )


async def _findings(session: AsyncSession, chosen: Period) -> AdminStatsFindings:
    weeks = _weeks(chosen.date_from, chosen.date_to)
    groups = await repository.finding_groups(session, weeks[0], weeks[-1])
    weekly: Counter[date] = Counter()
    modules: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    for group in groups:
        weekly[group.week] += group.detected
        modules[group.module] += group.detected
        categories[group.owasp_category] += group.detected
        severities[group.severity] += group.detected
    resolved = sum(group.resolved for group in groups)
    days = sum(group.days_to_resolve for group in groups)
    return AdminStatsFindings(
        detected=sum(weekly.values()),
        resolved=resolved,
        regressions=sum(group.regressions for group in groups),
        average_days_to_resolve=round(days / resolved, 2) if resolved else None,
        by_severity=SeverityCount(
            **{severity.value: severities[severity] for severity in Severity},
            total=sum(severities.values()),
        ),
        by_module=[
            ModuleCount(module=Module(module), detected=count)
            for module, count in _most_frequent(modules)
        ],
        by_owasp_category=[
            OwaspCount(owasp_category=category, detected=count)
            for category, count in _most_frequent(categories)
        ],
        weekly=[WeekCount(week=week, detected=weekly[week]) for week in weeks],
    )


def _most_frequent(counts: Counter[str]) -> list[tuple[str, int]]:
    """Most frequent first; the name breaks ties, so the order is stable."""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))
