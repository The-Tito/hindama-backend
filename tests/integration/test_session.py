"""The database session of each request: RLS settings, first access and transaction (ADR-013).

Runs the real app as `hindama_api` against PostgreSQL, with test-only endpoints.
"""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import UUID

import httpx
import pytest
from fastapi import APIRouter, FastAPI
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.api.dependencies import Admin, Analyst, AnyUser, DbSession
from hindama.core.errors import ConflictError
from hindama.models import DailyMetric, Project, User
from hindama.models.base import new_id
from hindama.models.enums import DailyMetricName
from tests.tokens import FakeUserPool


@pytest.fixture
def app(app: FastAPI) -> FastAPI:
    router = APIRouter()

    @router.get("/probe")
    async def probe(user: AnyUser, db: DbSession) -> dict[str, object]:
        settings = await db.execute(
            text(
                "SELECT current_setting('app.cognito_sub', true),"
                " current_setting('app.user_id', true), current_setting('app.role', true)"
            )
        )
        sub, user_id, role = settings.one()
        projects = await db.scalars(select(Project.id))
        return {
            "id": str(user.id),
            "settings": [sub, user_id, role],
            "projects": [str(p) for p in projects],
        }

    @router.post("/projects-probe")
    async def create_project(user: Analyst, db: DbSession, fail: bool = False) -> dict[str, str]:
        project = Project(
            owner_id=user.id,
            name="API de pedidos",
            base_url="https://api.ejemplo.com",
            host="api.ejemplo.com",
            verification_code=str(new_id()),
        )
        db.add(project)
        await db.flush()
        if fail:
            raise ConflictError("test.conflict", "Conflicto", "Falla después de escribir.")
        return {"id": str(project.id)}

    @router.get("/admin-probe")
    async def admin_only(user: Admin) -> dict[str, str]:
        return {"id": str(user.id)}

    app.include_router(router)
    return app


@pytest.fixture
async def subs(owner: AsyncEngine) -> AsyncIterator[list[str]]:
    """Cognito subs used by a test; their users (and projects) are deleted afterwards."""
    created: list[str] = []
    yield created
    async with owner.begin() as connection:
        await connection.execute(delete(User).where(User.cognito_sub.in_(created)))


class Session:
    """What Next.js sends on behalf of one Cognito user."""

    def __init__(
        self, client: httpx.AsyncClient, user_pool: FakeUserPool, sub: str, admin: bool = False
    ) -> None:
        token = user_pool.token(sub=sub, groups=["administradores"] if admin else [])
        self.client = client
        self.headers = {"Authorization": f"Bearer {token}"}

    async def get(self, path: str) -> httpx.Response:
        return await self.client.get(path, headers=self.headers)

    async def post(self, path: str) -> httpx.Response:
        return await self.client.post(path, headers=self.headers)


async def new_users_today(owner: AsyncEngine) -> int:
    async with owner.connect() as connection:
        value = await connection.scalar(
            select(DailyMetric.value).where(
                DailyMetric.date == datetime.now(UTC).date(),
                DailyMetric.metric == DailyMetricName.NEW_USERS,
            )
        )
    return value or 0


async def test_first_access_registers_the_user_once(
    anonymous_client: httpx.AsyncClient,
    user_pool: FakeUserPool,
    owner: AsyncEngine,
    subs: list[str],
) -> None:
    sub = str(new_id())
    subs.append(sub)
    session = Session(anonymous_client, user_pool, sub)
    before = await new_users_today(owner)

    first = (await session.get("/probe")).json()
    second = (await session.get("/probe")).json()

    assert first["id"] == second["id"]
    assert first["settings"] == [sub, first["id"], "analyst"]
    assert await new_users_today(owner) == before + 1


async def test_concurrent_first_accesses_create_one_user(
    anonymous_client: httpx.AsyncClient,
    user_pool: FakeUserPool,
    owner: AsyncEngine,
    subs: list[str],
) -> None:
    sub = str(new_id())
    subs.append(sub)
    session = Session(anonymous_client, user_pool, sub)

    responses = await asyncio.gather(*(session.get("/probe") for _ in range(5)))

    assert {r.status_code for r in responses} == {200}
    assert len({r.json()["id"] for r in responses}) == 1
    async with owner.connect() as connection:
        count = await connection.scalar(
            select(func.count()).select_from(User).where(User.cognito_sub == sub)
        )
    assert count == 1


async def test_each_analyst_sees_only_own_projects(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, subs: list[str]
) -> None:
    alice, bob = str(new_id()), str(new_id())
    subs += [alice, bob]
    alice_session = Session(anonymous_client, user_pool, alice)
    bob_session = Session(anonymous_client, user_pool, bob)

    alice_project = (await alice_session.post("/projects-probe")).json()["id"]
    bob_project = (await bob_session.post("/projects-probe")).json()["id"]

    assert (await alice_session.get("/probe")).json()["projects"] == [alice_project]
    assert (await bob_session.get("/probe")).json()["projects"] == [bob_project]


async def test_endpoint_error_rolls_back_and_success_commits(
    anonymous_client: httpx.AsyncClient,
    user_pool: FakeUserPool,
    owner: AsyncEngine,
    subs: list[str],
) -> None:
    sub = str(new_id())
    subs.append(sub)
    session = Session(anonymous_client, user_pool, sub)

    failed = await session.post("/projects-probe?fail=true")
    created = await session.post("/projects-probe")

    assert failed.status_code == 409
    assert created.status_code == 200
    # The commit happened before the response: another connection already sees it.
    async with owner.connect() as connection:
        owners = await connection.scalars(
            select(Project.id).join(User).where(User.cognito_sub == sub)
        )
        assert list(owners) == [UUID(created.json()["id"])]


async def test_roles_are_enforced(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, subs: list[str]
) -> None:
    analyst, admin = str(new_id()), str(new_id())
    subs += [analyst, admin]
    analyst_session = Session(anonymous_client, user_pool, analyst)
    admin_session = Session(anonymous_client, user_pool, admin, admin=True)

    assert (await analyst_session.get("/admin-probe")).json()["code"] == "role.forbidden"
    assert (await admin_session.post("/projects-probe")).json()["code"] == "role.forbidden"
    assert (await admin_session.get("/admin-probe")).status_code == 200
    probe = (await admin_session.get("/probe")).json()
    assert probe["settings"][2] == "admin"
    assert probe["projects"] == []
