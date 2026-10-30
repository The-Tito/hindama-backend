"""Application settings, read from environment variables (secrets never live in code)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration of the API process.

    Every variable uses the `HINDAMA_` prefix, e.g. `HINDAMA_DATABASE_URL`.
    """

    model_config = SettingsConfigDict(env_prefix="HINDAMA_", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"

    # SecretStr keeps the password out of reprs, logs and tracebacks.
    database_url: SecretStr = Field(
        description="SQLAlchemy URL with the asyncpg driver: postgresql+asyncpg://user:pass@host/db",
    )
    database_pool_size: int = Field(default=5, ge=1, le=50)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # Amazon Cognito: the API only validates access tokens (RF-07); it never holds a client secret.
    cognito_region: str = Field(pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    cognito_user_pool_id: str = Field(pattern=r"^[a-z]{2}(-[a-z]+)+-\d_[0-9A-Za-z]+$")
    cognito_client_id: str = Field(pattern=r"^[0-9a-z]{1,128}$")
    cognito_admin_group: str = "administradores"  # RN-04, RF-09
    jwks_cache_seconds: int = Field(default=3600, ge=60, le=86_400)

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cognito_issuer(self) -> str:
        return (
            f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"
        )

    @property
    def cognito_jwks_url(self) -> str:
        return f"{self.cognito_issuer}/.well-known/jwks.json"


@lru_cache
def get_settings() -> Settings:
    """Settings of the running process, read once."""
    return Settings()  # required fields come from the environment
