"""Name and email of the caller, read from Cognito on demand (ADR-015: not stored in the database).

Uses the `GetUser` action of the Cognito Identity Provider API with the caller's own access token:
it needs no AWS credentials and only returns the attributes of the token's owner. The token is
sent to Cognito and nowhere else; it is never logged.
"""

from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from hindama.core.errors import ServiceUnavailableError, UnauthenticatedError

log = structlog.get_logger("hindama.cognito")

GET_USER_TARGET = "AWSCognitoIdentityProviderService.GetUser"
AMZ_JSON = "application/x-amz-json-1.1"
# Cognito answers 400 with one of these when the token was revoked (global sign-out), the user was
# disabled or deleted after the token was issued: the session is no longer valid.
REJECTED_TOKEN_ERRORS = frozenset({"NotAuthorizedException", "UserNotFoundException"})


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    email: str


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
            attributes = _attributes(response.json())
        except (ValueError, TypeError, KeyError) as error:
            log.warning("cognito_bad_response", error=type(error).__name__)
            raise ServiceUnavailableError() from error
        name, email = attributes.get("name"), attributes.get("email")
        if not name or not email:  # the User Pool requires both (RF-01): a misconfiguration
            log.error("cognito_profile_incomplete", has_name=bool(name), has_email=bool(email))
            raise ServiceUnavailableError()
        return Profile(name=name, email=email)


def _error_type(response: httpx.Response) -> str | None:
    """`__type` may come qualified, e.g. `com.amazon...#NotAuthorizedException`."""
    try:
        kind = response.json().get("__type")
    except (ValueError, AttributeError):
        return None
    return kind.rpartition("#")[2] if isinstance(kind, str) else None


def _attributes(body: Any) -> dict[str, str]:
    return {item["Name"]: item["Value"] for item in body["UserAttributes"]}
