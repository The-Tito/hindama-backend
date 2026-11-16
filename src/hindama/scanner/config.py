"""Settings of the scanner process. Same `HINDAMA_` prefix as the API, but its own database role
(`hindama_scanner`) and no Cognito: the scanner never authenticates users."""

from typing import Literal

from pydantic import Field, IPvAnyAddress, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScannerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HINDAMA_", extra="ignore", hide_input_in_errors=True
    )

    environment: Literal["development", "test", "production"] = "development"
    # postgresql+asyncpg://hindama_scanner:...@host/hindama
    database_url: SecretStr
    database_pool_size: int = Field(default=10, ge=1, le=50)
    redis_url: SecretStr
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    # Same meaning as in the API (ADR-008): the platform never targets itself.
    own_ip_addresses: list[IPvAnyAddress] = Field(default_factory=list)
    # Runs per process (ADR-012, PT-02: 10 fit in ~34 MB of queue overhead).
    concurrency: int = Field(default=10, ge=1, le=20)
