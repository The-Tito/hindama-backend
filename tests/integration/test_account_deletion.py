"""`DELETE /me` (deleteAccount): CU-25, RF-88, RF-89, against PostgreSQL as `hindama_api`."""

from datetime import UTC, datetime
from uuid import UUID

import httpx
import pytest
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import DailyMetric, Finding, Identity, Operation, Project, Run, User
from hindama.models.enums import DailyMetricName
from tests.audit import actions, audit_entries
from tests.integration.conftest import Analyst
from tests.integration.test_projects import seed_activity
from tests.tokens import ADMIN_GROUP, FakeUserPool


async def user_id_of(owner: AsyncEngine, sub: str) -> UUID | None:
    async with owner.connect() as connection:
        return await connection.scalar(select(User.id).where(User.cognito_sub == sub))


async def deleted_accounts_today(owner: AsyncEngine) -> int:
    async with owner.connect() as connection:
        value = await connection.scalar(
            select(DailyMetric.value).where(
                DailyMetric.date == datetime.now(UTC).date(),
                DailyMetric.metric == DailyMetricName.DELETED_ACCOUNTS,
            )
        )
    return value or 0


def email_of(user_pool: FakeUserPool, analyst: Analyst) -> str:
    return user_pool.profile(analyst.sub)["email"]


async def test_deleting_the_account_removes_the_user_and_all_its_projects(
    ana: Analyst, user_pool: FakeUserPool, owner: AsyncEngine
) -> None:
    created = await ana.create()
    project_id = UUID(created["id"])
    await seed_activity(owner, project_id)
    user_id = await user_id_of(owner, ana.sub)
    async with AsyncSession(owner) as db, db.begin():  # a confirmed policy points to the user
        await db.execute(
            update(Operation).where(Operation.project_id == project_id).values(modified_by=user_id)
        )
    before = await deleted_accounts_today(owner)

    response = await ana.request(
        "DELETE", "/me", params={"confirmation": email_of(user_pool, ana).upper()}
    )

    assert response.status_code == 204
    assert response.content == b""
    assert await user_id_of(owner, ana.sub) is None
    async with owner.connect() as connection:
        for column in (Project.id, Identity.project_id, Run.project_id, Finding.project_id):
            count = await connection.scalar(select(func.count()).where(column == project_id))
            assert count == 0, column
    assert await deleted_accounts_today(owner) == before + 1
    assert actions(await audit_entries(owner, user_id=user_id)) == [
        "account_created",
        "project_created",
        "account_deleted",
    ]
    assert user_pool.deleted == [ana.sub]


async def test_another_analyst_keeps_everything(
    ana: Analyst, new_analyst: object, user_pool: FakeUserPool, owner: AsyncEngine
) -> None:
    beto: Analyst = new_analyst()  # type: ignore[operator]
    await beto.accept_terms()
    kept = await beto.create(name="API de Beto")

    response = await ana.request("DELETE", "/me", params={"confirmation": email_of(user_pool, ana)})

    assert response.status_code == 204
    assert (await beto.request("GET", f"/projects/{kept['id']}")).status_code == 200
    assert user_pool.deleted == [ana.sub]


async def test_a_wrong_email_deletes_nothing(
    ana: Analyst, user_pool: FakeUserPool, owner: AsyncEngine
) -> None:
    created = await ana.create()
    before = await deleted_accounts_today(owner)

    response = await ana.request("DELETE", "/me", params={"confirmation": "otro@ejemplo.com"})

    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "account.confirmation_mismatch"
    assert body["errors"][0]["field"] == "confirmation"
    assert await user_id_of(owner, ana.sub) is not None
    assert (await ana.request("GET", f"/projects/{created['id']}")).status_code == 200
    assert await deleted_accounts_today(owner) == before
    assert user_pool.deleted == []


async def test_an_active_run_is_a_conflict(
    ana: Analyst, user_pool: FakeUserPool, owner: AsyncEngine
) -> None:
    created = await ana.create()
    async with AsyncSession(owner) as db, db.begin():
        db.add(
            Run(
                project_id=UUID(created["id"]),
                number=1,
                config={"modules": ["configuration"]},
                status="queued",
            )
        )

    response = await ana.request("DELETE", "/me", params={"confirmation": email_of(user_pool, ana)})

    assert response.status_code == 409
    assert response.json()["code"] == "account.active_run"
    assert await user_id_of(owner, ana.sub) is not None
    assert user_pool.deleted == []


async def test_a_finished_run_does_not_block(
    ana: Analyst, user_pool: FakeUserPool, owner: AsyncEngine
) -> None:
    created = await ana.create()
    async with AsyncSession(owner) as db, db.begin():
        db.add(
            Run(
                project_id=UUID(created["id"]),
                number=1,
                config={"modules": ["configuration"]},
                status="cancelled",
                end_reason="cancelled_by_user",
                finished_at=datetime.now(UTC),
            )
        )

    response = await ana.request("DELETE", "/me", params={"confirmation": email_of(user_pool, ana)})

    assert response.status_code == 204


async def test_cognito_down_after_deleting_the_data_can_be_retried(
    ana: Analyst, user_pool: FakeUserPool, owner: AsyncEngine
) -> None:
    """CU-25 E3: the data is already gone; the retry enters an empty account and finishes."""
    await ana.create()
    before = await deleted_accounts_today(owner)
    user_pool.delete_user_response = (500, {"__type": "InternalErrorException"})

    failed = await ana.request("DELETE", "/me", params={"confirmation": email_of(user_pool, ana)})

    assert failed.status_code == 503
    assert failed.json()["code"] == "account.deletion_incomplete"
    assert await user_id_of(owner, ana.sub) is None
    assert await deleted_accounts_today(owner) == before + 1

    user_pool.delete_user_response = None
    retried = await ana.request("DELETE", "/me", params={"confirmation": email_of(user_pool, ana)})

    assert retried.status_code == 204
    assert user_pool.deleted == [ana.sub]


async def test_a_user_already_deleted_in_cognito_counts_as_deleted(
    ana: Analyst, user_pool: FakeUserPool
) -> None:
    user_pool.delete_user_response = (400, {"__type": "UserNotFoundException"})

    response = await ana.request("DELETE", "/me", params={"confirmation": email_of(user_pool, ana)})

    assert response.status_code == 204


async def test_cognito_down_before_deleting_deletes_nothing(
    ana: Analyst, user_pool: FakeUserPool, owner: AsyncEngine
) -> None:
    user_pool.get_user_response = (500, {"__type": "InternalErrorException"})

    response = await ana.request("DELETE", "/me", params={"confirmation": "ana@ejemplo.com"})

    assert response.status_code == 503
    assert response.json()["code"] == "service.unavailable"
    assert await user_id_of(owner, ana.sub) is not None


async def test_the_administrator_cannot_delete_its_account(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, subs: list[str]
) -> None:
    subs.append(sub := "0192e3a0-aaaa-7000-8000-00000000ad01")
    token = user_pool.token(sub=sub, groups=[ADMIN_GROUP])

    response = await anonymous_client.delete(
        "/me",
        params={"confirmation": user_pool.profile(sub)["email"]},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "role.forbidden"
    assert user_pool.deleted == []


@pytest.mark.parametrize("confirmation", ["", "a" * 255, "ana@ejemplo.com\u0000"])
async def test_invalid_confirmations(ana: Analyst, confirmation: str) -> None:
    response = await ana.request("DELETE", "/me", params={"confirmation": confirmation})

    assert response.status_code == 422
    assert response.json()["code"] == "validation.failed"


async def test_without_a_session(anonymous_client: httpx.AsyncClient) -> None:
    response = await anonymous_client.delete("/me", params={"confirmation": "ana@ejemplo.com"})

    assert response.status_code == 401
