"""Application settings, read from environment variables (secrets never live in code)."""

import base64
import binascii
from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, IPvAnyAddress, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from hindama.core.audit import HostHasher
from hindama.core.credentials import KEY_BYTES, CredentialCipher


def _decode_keys(keys: dict[int, SecretStr], version: int, name: str) -> dict[int, bytes]:
    """Checks a versioned key set ({"1": "<32 bytes in base64>"}) and decodes it.

    Only the version is named in errors: pydantic would otherwise echo the input value.
    """
    decoded = {}
    for number, key in keys.items():
        if not 1 <= number <= 255:
            raise ValueError(f"{name} key version {number} must go from 1 to 255")
        try:
            raw = base64.b64decode(key.get_secret_value(), validate=True)
        except binascii.Error:
            raise ValueError(f"{name} key {number} is not valid base64") from None
        if len(raw) != KEY_BYTES:
            raise ValueError(f"{name} key {number} must be {KEY_BYTES} bytes long")
        decoded[number] = raw
    if version not in keys:
        raise ValueError(f"{name}_key_version is not among {name}_keys")
    return decoded


class CredentialKeySettings(BaseSettings):
    """The credential keys, shared by the API (encrypts) and the scanner (decrypts, RN-11)."""

    # A configuration error must not print what it read: it may hold keys and passwords.
    model_config = SettingsConfigDict(
        env_prefix="HINDAMA_", extra="ignore", hide_input_in_errors=True
    )

    # AES-256-GCM master keys of the identities' credentials (ADR-007), by version, base64-encoded:
    # {"1": "<32 bytes in base64>"}. New credentials use `credential_key_version`; older versions
    # stay loaded until a rotation re-encrypts their rows. Never in the database or in code.
    credential_keys: dict[int, SecretStr] = Field(min_length=1)
    credential_key_version: int = Field(default=1, ge=1, le=255)

    # HMAC-SHA256 keys of the audit log (ADR-015, RF-83), same format: the log stores the HMAC of a
    # project's host, never the host. New entries use `audit_hmac_key_version`; older versions stay
    # loaded so the administrator can still search old entries by host (RF-84). In SSM:
    # /hindama/backend/audit-hmac-keys.
    audit_hmac_keys: dict[int, SecretStr] = Field(min_length=1)
    audit_hmac_key_version: int = Field(default=1, ge=1, le=255)

    @model_validator(mode="after")
    def _check_keys(self) -> Self:
        _decode_keys(self.credential_keys, self.credential_key_version, "credential")
        _decode_keys(self.audit_hmac_keys, self.audit_hmac_key_version, "audit_hmac")
        return self

    def credential_cipher(self) -> CredentialCipher:
        keys = _decode_keys(self.credential_keys, self.credential_key_version, "credential")
        return CredentialCipher(keys, self.credential_key_version)

    def host_hasher(self) -> HostHasher:
        keys = _decode_keys(self.audit_hmac_keys, self.audit_hmac_key_version, "audit_hmac")
        return HostHasher(keys, self.audit_hmac_key_version)


class Settings(CredentialKeySettings):
    """All configuration of the API process.

    Every variable uses the `HINDAMA_` prefix, e.g. `HINDAMA_DATABASE_URL`.
    """

    # A configuration error must not print what it read: it may hold keys and passwords.
    model_config = SettingsConfigDict(
        env_prefix="HINDAMA_", extra="ignore", hide_input_in_errors=True
    )

    environment: Literal["development", "test", "production"] = "development"

    # SecretStr keeps the password out of reprs, logs and tracebacks.
    database_url: SecretStr = Field(
        description="SQLAlchemy URL with the asyncpg driver: postgresql+asyncpg://user:pass@host/db",
    )
    database_pool_size: int = Field(default=5, ge=1, le=50)

    # Redis of the run queue (ADR-012), with its password: redis://:pass@redis:6379/0. Without it
    # the API answers 503 when launching a run; everything else works.
    redis_url: SecretStr | None = None
    # RNF-09: requests per minute per user, counted in that Redis. Without Redis, no limit.
    rate_limit_per_minute: int = Field(default=100, ge=1)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # Amazon Cognito: the API only validates access tokens (RF-07); it never holds a client secret.
    cognito_region: str = Field(pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    cognito_user_pool_id: str = Field(pattern=r"^[a-z]{2}(-[a-z]+)+-\d_[0-9A-Za-z]+$")
    cognito_client_id: str = Field(pattern=r"^[0-9a-z]{1,128}$")
    cognito_admin_group: str = "administradores"  # RN-04, RF-09
    jwks_cache_seconds: int = Field(default=3600, ge=60, le=86_400)

    # Version of the responsible-use terms in force (RF-16, RN-12). The text is published by the
    # frontend; changing this value asks every user to accept again.
    terms_version: str = Field(default="2026-10-30", pattern=r"^\d{4}-\d{2}-\d{2}$")

    # Hindama's own public addresses (the Elastic IPs of frontend and backend): nobody may point the
    # platform at itself (ADR-008). JSON list, e.g. ["203.0.113.10", "203.0.113.11"].
    own_ip_addresses: list[IPvAnyAddress] = Field(default_factory=list)

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cognito_issuer(self) -> str:
        return (
            f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"
        )

    @property
    def cognito_idp_endpoint(self) -> str:
        """Cognito Identity Provider API, used for `GetUser`."""
        return f"https://cognito-idp.{self.cognito_region}.amazonaws.com/"

    @property
    def cognito_jwks_url(self) -> str:
        return f"{self.cognito_issuer}/.well-known/jwks.json"


@lru_cache
def get_settings() -> Settings:
    """Settings of the running process, read once."""
    return Settings()  # required fields come from the environment
