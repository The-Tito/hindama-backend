"""The caller's Cognito account: GetUser (ADR-015, not stored) and DeleteUser (RF-88)."""

import json

import httpx
import pytest

from hindama.core.cognito import AMZ_JSON, GET_USER_TARGET, Profile
from hindama.core.errors import ServiceUnavailableError, UnauthenticatedError
from tests.tokens import FakeUserPool


async def test_returns_name_and_email_of_the_token_owner(user_pool: FakeUserPool) -> None:
    token = user_pool.token(sub="abc-123")
    user_pool.attributes["abc-123"] = {"name": "Ana López", "email": "ana@ejemplo.com"}

    profile = await user_pool.profile_client().get(token)

    assert profile == Profile(name="Ana López", email="ana@ejemplo.com")
    (request,) = user_pool.get_user_requests
    assert request.headers["X-Amz-Target"] == GET_USER_TARGET
    assert request.headers["Content-Type"] == AMZ_JSON
    # The token travels only in the body, and no AWS credentials are needed.
    assert json.loads(request.content) == {"AccessToken": token}
    assert "authorization" not in request.headers


@pytest.mark.parametrize(
    "kind",
    [
        "NotAuthorizedException",
        "com.amazonaws.cognito.identity.idp.model#NotAuthorizedException",
        "UserNotFoundException",
    ],
)
async def test_revoked_token_or_deleted_user_is_unauthenticated(
    user_pool: FakeUserPool, kind: str
) -> None:
    user_pool.get_user_response = (400, {"__type": kind, "message": "Access Token revoked"})

    with pytest.raises(UnauthenticatedError) as raised:
        await user_pool.profile_client().get(user_pool.token())

    assert raised.value.code == "auth.invalid_token"


@pytest.mark.parametrize(
    "response",
    [
        (400, {"__type": "InvalidParameterException"}),
        (500, {"__type": "InternalErrorException"}),
        (503, {}),
        (200, {"Username": "x"}),  # no attributes
        (200, {"UserAttributes": [{"Name": "name", "Value": "Ana"}]}),  # no email
        (200, {"UserAttributes": [{"Name": "email", "Value": "a@ejemplo.com"}]}),  # no name
    ],
)
async def test_other_failures_are_service_unavailable(
    user_pool: FakeUserPool, response: tuple[int, dict[str, object]]
) -> None:
    user_pool.get_user_response = response

    with pytest.raises(ServiceUnavailableError):
        await user_pool.profile_client().get(user_pool.token())


async def test_unreachable_cognito_is_service_unavailable(user_pool: FakeUserPool) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout", request=request)

    client = user_pool.profile_client()
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(fail))

    with pytest.raises(ServiceUnavailableError):
        await client.get(user_pool.token())


async def test_non_json_answer_is_service_unavailable(user_pool: FakeUserPool) -> None:
    client = user_pool.profile_client()
    client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"<html>"))
    )

    with pytest.raises(ServiceUnavailableError):
        await client.get(user_pool.token())


async def test_the_token_is_never_logged(
    user_pool: FakeUserPool, capsys: pytest.CaptureFixture[str]
) -> None:
    token = user_pool.token()
    user_pool.get_user_response = (400, {"__type": "NotAuthorizedException"})

    with pytest.raises(UnauthenticatedError):
        await user_pool.profile_client().get(token)

    output = capsys.readouterr().out
    assert "cognito_rejected_token" in output
    assert token.split(".")[1] not in output


# ------------------------------------------------------------------ DeleteUser (CU-25, RF-88)


async def test_delete_removes_the_token_owner(user_pool: FakeUserPool) -> None:
    await user_pool.profile_client().delete(user_pool.token(sub="abc-123"))

    assert user_pool.deleted == ["abc-123"]


async def test_delete_of_a_user_already_deleted_succeeds(user_pool: FakeUserPool) -> None:
    user_pool.delete_user_response = (400, {"__type": "UserNotFoundException"})

    await user_pool.profile_client().delete(user_pool.token())


@pytest.mark.parametrize(
    "response",
    [
        (400, {"__type": "NotAuthorizedException"}),
        (500, {"__type": "InternalErrorException"}),
        (503, {}),
    ],
)
async def test_delete_failures_are_service_unavailable(
    user_pool: FakeUserPool, response: tuple[int, dict[str, object]]
) -> None:
    user_pool.delete_user_response = response

    with pytest.raises(ServiceUnavailableError):
        await user_pool.profile_client().delete(user_pool.token())


async def test_delete_with_unreachable_cognito_is_service_unavailable(
    user_pool: FakeUserPool, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout", request=request)

    client = user_pool.profile_client()
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(fail))
    token = user_pool.token()

    with pytest.raises(ServiceUnavailableError):
        await client.delete(token)

    assert token.split(".")[1] not in capsys.readouterr().out


# ------------------------------------------------------------------ second factor (RF-85, RF-86)


@pytest.mark.parametrize(
    ("settings", "enabled"),
    [
        (None, False),  # absent: no second factor
        ([], False),
        (["SMS_MFA"], False),
        (["SOFTWARE_TOKEN_MFA"], True),
        (["SMS_MFA", "SOFTWARE_TOKEN_MFA"], True),
    ],
)
async def test_mfa_enabled_means_the_totp_is_active(
    user_pool: FakeUserPool, settings: list[str] | None, enabled: bool
) -> None:
    body: dict[str, object] = {
        "UserAttributes": [
            {"Name": "name", "Value": "Ana"},
            {"Name": "email", "Value": "ana@ejemplo.com"},
        ]
    }
    if settings is not None:
        body["UserMFASettingList"] = settings
    user_pool.get_user_response = (200, body)

    profile = await user_pool.profile_client().get(user_pool.token())

    assert profile.mfa_enabled is enabled


async def test_a_malformed_mfa_list_is_service_unavailable(user_pool: FakeUserPool) -> None:
    user_pool.get_user_response = (
        200,
        {
            "UserAttributes": [
                {"Name": "name", "Value": "Ana"},
                {"Name": "email", "Value": "ana@ejemplo.com"},
            ],
            "UserMFASettingList": "SOFTWARE_TOKEN_MFA",
        },
    )

    with pytest.raises(ServiceUnavailableError):
        await user_pool.profile_client().get(user_pool.token())
