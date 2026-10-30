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

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    """Settings of the running process, read once."""
    return Settings()  # required fields come from the environment
