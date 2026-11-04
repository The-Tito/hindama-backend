"""Schemas of `/projects` (components `ProjectCreate`, `ProjectUpdate`, `Project`, ...)."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import MISSING, Field, StringConstraints, field_validator

from hindama.models.enums import Module, RunStatus, VerificationStatus
from hindama.schemas.common import ContractModel, Warning

# RF-10. The name is trimmed before checking its length.
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
Description = Annotated[str, StringConstraints(max_length=500)]
BaseUrl = Annotated[
    str, StringConstraints(max_length=2048), Field(json_schema_extra={"format": "uri"})
]


def _blank_to_none(value: str | None) -> str | None:
    """An empty description is no description."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


class ProjectCreate(ContractModel):
    name: Name
    description: Description | None = None
    base_url: BaseUrl

    _description = field_validator("description")(_blank_to_none)


class ProjectUpdate(ContractModel):
    """Only the fields sent change. `MISSING` keeps "not sent" apart from `null`."""

    name: Name | MISSING = MISSING
    description: Description | MISSING | None = MISSING
    base_url: BaseUrl | MISSING = MISSING

    _description = field_validator("description")(_blank_to_none)


class ContractVersionSummary(ContractModel):
    id: UUID
    number: int = Field(ge=1)
    source: Literal["file", "url"]
    openapi_version: str
    operation_count: int = Field(ge=0)
    imported_at: datetime


class RunSummary(ContractModel):
    id: UUID
    number: int = Field(ge=1)
    status: RunStatus
    created_at: datetime
    finished_at: datetime | None


class SeverityCount(ContractModel):
    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)
    info: int = Field(ge=0)
    total: int = Field(ge=0)


MissingRequirement = Literal[
    "project_not_verified",
    "no_contract",
    "insufficient_identities",
    "no_admin_identity",
    "no_resources",
    "policy_unconfirmed",
]


class ModuleAvailability(ContractModel):
    module: Module
    risk: Literal["low", "medium", "high"]
    available: bool
    missing: list[MissingRequirement]


class Project(ContractModel):
    id: UUID
    name: str
    description: str | None
    base_url: str
    host: str
    verification_status: VerificationStatus
    verified_at: datetime | None
    concluded: bool
    current_contract: ContractVersionSummary | None
    last_run: RunSummary | None
    open_findings_by_severity: SeverityCount
    modules: list[ModuleAvailability]
    warnings: list[Warning]
    created_at: datetime
    updated_at: datetime


class ProjectSummary(ContractModel):
    id: UUID
    name: str
    base_url: str
    verification_status: VerificationStatus
    concluded: bool
    last_run_at: datetime | None
    open_findings: int = Field(ge=0)
    created_at: datetime


class ProjectPage(ContractModel):
    items: list[ProjectSummary]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
