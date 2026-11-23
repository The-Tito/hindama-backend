"""The administrator's statistics (CU-20; RF-78, RF-79, RF-80, RF-89).

The metric tables are shared by every test and have no owner, so each test writes its own facts in
a past year nobody else uses, and removes them afterwards.
"""

from collections.abc import AsyncIterator, Callable, Coroutine
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete, extract, insert
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.models import DailyMetric, FindingMetric
from hindama.models.base import new_id
from tests.integration.conftest import Analyst
from tests.integration.test_audit_log import admin, analyst  # noqa: F401 - fixtures

Write = Callable[..., Coroutine[Any, Any, None]]


@pytest.fixture
async def facts(owner: AsyncEngine) -> AsyncIterator[Write]:
    """Writes anonymous facts as the scanner and the API would; removes the years it touched."""
    years: set[int] = set()

    async def write(
        daily: dict[tuple[date, str], int] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        async with owner.begin() as connection:
            for (day, metric), value in (daily or {}).items():
                years.add(day.year)
                await connection.execute(
                    insert(DailyMetric).values(date=day, metric=metric, value=value)
                )
            for finding in findings or []:
                years.add(finding["week"].year)
                await connection.execute(insert(FindingMetric).values(id=new_id(), **finding))

    yield write
    async with owner.begin() as connection:
        for year in years:
            await connection.execute(
                delete(DailyMetric).where(extract("year", DailyMetric.date) == year)
            )
            await connection.execute(
                delete(FindingMetric).where(extract("year", FindingMetric.week) == year)
            )


async def stats(client: Analyst, **params: Any) -> dict[str, Any]:
    response = await client.request("GET", "/admin/stats", params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def finding(
    week: date,
    module: str,
    owasp: str,
    severity: str,
    days: int | None = None,
    regressions: int = 0,
) -> dict[str, Any]:
    return {
        "week": week,
        "module": module,
        "owasp_category": owasp,
        "severity": severity,
        "days_to_resolve": days,
        "regressions": regressions,
    }


# ------------------------------------------------------------------ who (RF-80, RF-84)


async def test_only_the_administrator_reads_the_statistics(analyst: Analyst) -> None:  # noqa: F811
    response = await analyst.request("GET", "/admin/stats")

    assert response.status_code == 403
    assert response.json()["code"] == "role.forbidden"


# ------------------------------------------------------------------ figures (RF-78)

MONDAY = date(2001, 3, 5)  # a Monday


async def test_the_figures_of_a_period_by_day(admin: Analyst, facts: Write) -> None:  # noqa: F811
    await facts(
        daily={
            (MONDAY - timedelta(days=40), "new_users"): 5,  # before: only in the total
            (MONDAY - timedelta(days=40), "deleted_accounts"): 1,
            (MONDAY, "new_users"): 2,
            (MONDAY, "projects_created"): 3,
            (MONDAY, "runs_started"): 4,
            (MONDAY + timedelta(days=2), "runs_started"): 1,
            (MONDAY + timedelta(days=2), "runs_cancelled"): 1,
            (MONDAY + timedelta(days=2), "runs_failed"): 2,
            (MONDAY + timedelta(days=2), "deleted_accounts"): 1,
            (MONDAY + timedelta(days=7), "runs_started"): 9,  # after: not counted
        },
        findings=[
            finding(MONDAY, "object_access", "API1:2023", "critical", days=2),
            finding(MONDAY, "object_access", "API1:2023", "high", days=3, regressions=1),
            finding(MONDAY, "configuration", "API8:2023", "low"),
            finding(MONDAY + timedelta(weeks=1), "configuration", "API8:2023", "low"),  # after
        ],
    )

    body = await stats(
        admin, date_from=MONDAY.isoformat(), date_to=(MONDAY + timedelta(days=2)).isoformat()
    )

    assert body["period"] == {"date_from": "2001-03-05", "date_to": "2001-03-07", "group": "day"}
    assert body["users"] == {"total": 5, "new": 2, "deleted": 1}  # 5 - 1 + 2 - 1
    assert body["projects"] == {"created": 3}
    assert body["runs"] == {"started": 5, "cancelled": 1, "failed": 2}
    assert [a["start"] for a in body["activity"]] == ["2001-03-05", "2001-03-06", "2001-03-07"]
    assert body["activity"][1] == {  # an empty day is still there
        "start": "2001-03-06",
        "new_users": 0,
        "deleted_accounts": 0,
        "projects_created": 0,
        "runs_started": 0,
        "runs_cancelled": 0,
        "runs_failed": 0,
    }
    assert body["activity"][0]["runs_started"] == 4
    assert body["findings"] == {
        "detected": 3,
        "resolved": 2,
        "regressions": 1,
        "average_days_to_resolve": 2.5,
        "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0, "total": 3},
        "by_module": [
            {"module": "object_access", "detected": 2},
            {"module": "configuration", "detected": 1},
        ],
        "by_owasp_category": [
            {"owasp_category": "API1:2023", "detected": 2},
            {"owasp_category": "API8:2023", "detected": 1},
        ],
        "weekly": [{"week": "2001-03-05", "detected": 3}],
    }


async def test_weeks_start_on_monday(admin: Analyst, facts: Write) -> None:  # noqa: F811
    monday = date(2002, 3, 4)
    await facts(
        daily={
            (monday - timedelta(days=1), "runs_started"): 1,  # Sunday: the week before
            (monday + timedelta(days=6), "runs_started"): 2,  # Sunday: this week
            (monday + timedelta(days=8), "runs_started"): 4,
        },
        findings=[
            finding(monday - timedelta(weeks=1), "authentication", "API2:2023", "high"),
            finding(monday + timedelta(weeks=1), "authentication", "API2:2023", "high"),
        ],
    )

    body = await stats(
        admin,
        date_from=(monday - timedelta(days=1)).isoformat(),  # a Sunday
        date_to=(monday + timedelta(days=8)).isoformat(),  # a Tuesday
        group="week",
    )

    assert [(a["start"], a["runs_started"]) for a in body["activity"]] == [
        ("2002-02-25", 1),  # partial weeks at both ends
        ("2002-03-04", 2),
        ("2002-03-11", 4),
    ]
    assert body["runs"]["started"] == 7
    # The Monday of `date_from` opens the findings' weeks: the week of that Sunday counts.
    assert body["findings"]["weekly"] == [
        {"week": "2002-02-25", "detected": 1},
        {"week": "2002-03-04", "detected": 0},
        {"week": "2002-03-11", "detected": 1},
    ]


async def test_an_empty_period(admin: Analyst) -> None:  # noqa: F811
    body = await stats(admin, date_from="1990-01-01", date_to="1990-01-03")

    assert body["users"] == {"total": 0, "new": 0, "deleted": 0}
    assert body["runs"] == {"started": 0, "cancelled": 0, "failed": 0}
    assert len(body["activity"]) == 3
    assert body["findings"]["detected"] == 0
    assert body["findings"]["average_days_to_resolve"] is None
    assert body["findings"]["by_module"] == []
    assert body["findings"]["by_owasp_category"] == []
    assert body["findings"]["by_severity"]["total"] == 0


async def test_by_default_the_last_thirty_days(admin: Analyst) -> None:  # noqa: F811
    today = datetime.now(UTC).date()

    body = await stats(admin)

    assert body["period"] == {
        "date_from": (today - timedelta(days=29)).isoformat(),
        "date_to": today.isoformat(),
        "group": "day",
    }
    assert len(body["activity"]) == 30


# ------------------------------------------------------------------ anonymous (RF-79, RF-89)


async def test_deleting_a_project_changes_no_figure(
    admin: Analyst,  # noqa: F811
    analyst: Analyst,  # noqa: F811
) -> None:
    project = await analyst.create()
    before = await stats(admin)

    deleted = await analyst.request(
        "DELETE", f"/projects/{project['id']}", params={"confirmation": project["name"]}
    )

    assert deleted.status_code == 204, deleted.text
    assert await stats(admin) == before


async def test_nothing_points_to_an_analyst_or_a_project(
    admin: Analyst,  # noqa: F811
    analyst: Analyst,  # noqa: F811
) -> None:
    project = await analyst.create()
    me = (await analyst.request("GET", "/me")).json()

    text = (await admin.request("GET", "/admin/stats")).text

    for value in (project["id"], project["host"], project["name"], me["id"], me["email"]):
        assert value not in text


# ------------------------------------------------------------------ the period


@pytest.mark.parametrize(
    ("params", "field"),
    [
        ({"date_from": "2026-11-20", "date_to": "2026-11-19"}, "date_to"),
        ({"date_from": "2025-01-01", "date_to": "2026-01-02"}, "date_from"),  # 367 days
        ({"date_from": "2999-01-01"}, "date_to"),  # after today, the default end
    ],
)
async def test_an_invalid_period(admin: Analyst, params: dict[str, str], field: str) -> None:  # noqa: F811
    response = await admin.request("GET", "/admin/stats", params=params)

    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation.failed"
    assert [(e["field"], e["code"]) for e in body["errors"]] == [(field, "validation.format")]


@pytest.mark.parametrize("value", ["0", "1700000000", "2026-11-20T00:00:00Z", "20-11-2026"])
async def test_a_date_is_only_year_month_day(admin: Analyst, value: str) -> None:  # noqa: F811
    response = await admin.request("GET", "/admin/stats", params={"date_from": value})

    assert response.status_code == 422


async def test_a_whole_year_is_allowed(admin: Analyst) -> None:  # noqa: F811
    body = await stats(admin, date_from="2003-01-01", date_to="2004-01-01", group="week")

    assert body["period"]["date_to"] == "2004-01-01"  # 366 days


@pytest.mark.parametrize(
    ("params", "days"),
    [({"date_to": "0001-01-05"}, 5), ({"date_from": "9999-12-25", "date_to": "9999-12-31"}, 7)],
)
async def test_the_ends_of_the_calendar(
    admin: Analyst,  # noqa: F811
    params: dict[str, str],
    days: int,
) -> None:
    body = await stats(admin, **params)

    assert len(body["activity"]) == days
