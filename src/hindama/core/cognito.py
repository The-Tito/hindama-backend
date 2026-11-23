"""The caller's own Cognito account: name and email on demand, and its deletion.

Name and email are read with `GetUser` (ADR-015: not stored in the database); the account is
deleted with `DeleteUser` (CU-25, RF-88). Both actions of the Cognito Identity Provider API use the
caller's own access token: they need no AWS credentials and only reach the token's owner. The token
is sent to Cognito and nowhere else; it is never logged.
"""

from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from hindama.core.errors import ServiceUnavailableError, UnauthenticatedError

log = structlog.get_logger("hindama.cognito")

GET_USER_TARGET = "AWSCognitoIdentityProviderService.GetUser"
DELETE_USER_TARGET = "AWSCognitoIdentityProviderService.DeleteUser"
AMZ_JSON = "application/x-amz-json-1.1"
# In `UserMFASettingList` when the user has the TOTP active: Cognito asks for it at every sign-in.
TOTP = "SOFTWARE_TOKEN_MFA"
# Cognito answers 400 with one of these when the token was revoked (global sign-out), the user was
# disabled or deleted after the token was issued: the session is no longer valid.
REJECTED_TOKEN_ERRORS = frozenset({"NotAuthorizedException", "UserNotFoundException"})


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    email: str
    mfa_enabled: bool = False  # TOTP active (RF-85); required for administrators (RF-86, ADR-018)


class ProfileClient:
    def __init__(self, *, endpoint: str, http: httpx.AsyncClient) -> None:
        self._endpoint = endpoint
        self._http = http

    async def get(self, access_token: str) -> Profile:
        try:
            response = await self._http.post(
                self._endpoint,
                json={"AccessToken": access_token},
                headers={"Content-Type": AMZ_JSON, "X-Amz-Target": GET_USER_TARGET},
            )
        except httpx.HTTPError as error:
            log.warning("cognito_unavailable", error=type(error).__name__)
            raise ServiceUnavailableError() from error

        if response.status_code == 400 and _error_type(response) in REJECTED_TOKEN_ERRORS:
            log.info("cognito_rejected_token", reason=_error_type(response))
            raise UnauthenticatedError("auth.invalid_token")
        if response.status_code != 200:
            log.warning("cognito_error", status=response.status_code, reason=_error_type(response))
            raise ServiceUnavailableError()

        try:
            body = response.json()
            attributes = _attributes(body)
            mfa_enabled = _totp_active(body)
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            log.warning("cognito_bad_response", error=type(error).__name__)
            raise ServiceUnavailableError() from error
        name, email = attributes.get("name"), attributes.get("email")
        if not name or not email:  # the User Pool requires both (RF-01): a misconfiguration
            log.error("cognito_profile_incomplete", has_name=bool(name), has_email=bool(email))
            raise ServiceUnavailableError()
        return Profile(name=name, email=email, mfa_enabled=mfa_enabled)

    async def delete(self, access_token: str) -> None:
        """Deletes the token's owner (RF-88). Raises ServiceUnavailableError if it may still exist.

        `UserNotFoundException` means a previous attempt already deleted it: the goal is met.
        """
        try:
            response = await self._http.post(
                self._endpoint,
                json={"AccessToken": access_token},
                headers={"Content-Type": AMZ_JSON, "X-Amz-Target": DELETE_USER_TARGET},
            )
        except httpx.HTTPError as error:
            log.warning("cognito_delete_unavailable", error=type(error).__name__)
            raise ServiceUnavailableError() from error
        if response.status_code == 200:
            return
        reason = _error_type(response)
        if response.status_code == 400 and reason == "UserNotFoundException":
            log.info("cognito_user_already_deleted")
            return
        log.warning("cognito_delete_error", status=response.status_code, reason=reason)
        raise ServiceUnavailableError()


def _error_type(response: httpx.Response) -> str | None:
    """`__type` may come qualified, e.g. `com.amazon...#NotAuthorizedException`."""
    try:
        kind = response.json().get("__type")
    except (ValueError, AttributeError):
        return None
    return kind.rpartition("#")[2] if isinstance(kind, str) else None


def _attributes(body: Any) -> dict[str, str]:
    return {item["Name"]: item["Value"] for item in body["UserAttributes"]}


def _totp_active(body: Any) -> bool:
    """`UserMFASettingList` is absent when the user has no second factor."""
    settings = body.get("UserMFASettingList", [])
    if not isinstance(settings, list):
        raise TypeError("UserMFASettingList is not a list")
    return TOTP in settings
