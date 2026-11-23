"""Second factor (CU-22, RF-85, RF-86, ADR-018): `Me.mfa_enabled` and the panel requires it."""

import httpx
import pytest

from tests.integration.conftest import Analyst
from tests.integration.test_audit_log import admin  # noqa: F401 - fixture
from tests.tokens import FakeUserPool

ADMIN_PATHS = ("/admin/audit-log", "/admin/stats")


@pytest.mark.parametrize("path", ADMIN_PATHS)
async def test_an_administrator_without_totp_is_sent_to_activate_it(
    admin: Analyst,  # noqa: F811
    user_pool: FakeUserPool,
    path: str,
) -> None:
    user_pool.mfa.discard(admin.sub)

    response = await admin.request("GET", path)

    assert response.status_code == 403
    assert response.json()["code"] == "auth.mfa_required"


@pytest.mark.parametrize("path", ADMIN_PATHS)
async def test_an_administrator_with_totp_enters(admin: Analyst, path: str) -> None:  # noqa: F811
    response = await admin.request("GET", path)

    assert response.status_code == 200


async def test_me_reports_the_totp_status(
    admin: Analyst,  # noqa: F811
    user_pool: FakeUserPool,
    new_analyst: object,
) -> None:
    ana: Analyst = new_analyst()  # type: ignore[operator]

    assert (await ana.request("GET", "/me")).json()["mfa_enabled"] is False
    assert (await admin.request("GET", "/me")).json()["mfa_enabled"] is True
    user_pool.mfa.add(ana.sub)
    assert (await ana.request("GET", "/me")).json()["mfa_enabled"] is True


async def test_an_analyst_is_rejected_by_role_without_asking_cognito(
    new_analyst: object, user_pool: FakeUserPool
) -> None:
    ana: Analyst = new_analyst()  # type: ignore[operator]
    user_pool.mfa.add(ana.sub)  # the second factor does not make anyone an administrator

    response = await ana.request("GET", "/admin/stats")

    assert response.status_code == 403
    assert response.json()["code"] == "role.forbidden"
    assert user_pool.get_user_requests == []


async def test_cognito_down_does_not_let_an_administrator_in(
    admin: Analyst,  # noqa: F811
    user_pool: FakeUserPool,
) -> None:
    user_pool.get_user_response = (500, {"__type": "InternalErrorException"})

    response = await admin.request("GET", "/admin/audit-log")

    assert response.status_code == 503
    assert response.json()["code"] == "service.unavailable"


async def test_without_a_session(anonymous_client: httpx.AsyncClient) -> None:
    assert (await anonymous_client.get("/admin/stats")).status_code == 401
