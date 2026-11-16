"""Schemas of `/contracts` and `/operations` (components `ContractVersion`, `ContractPage`,
`Operation`, `OperationPage`...). Texts that come from the analyst's document are untrusted."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints

from hindama.models.enums import HttpMethod, Policy
from hindama.schemas.common import SINGLE_LINE, ContractModel, Warning
from hindama.schemas.projects import ContractVersionSummary


class OperationRef(ContractModel):
    id: UUID
    method: HttpMethod
    path: str


class ContractChanges(ContractModel):
    previous_version: int
    added: list[OperationRef]
    modified: list[OperationRef]
    removed: list[OperationRef]


class ContractVersion(ContractModel):
    id: UUID
    number: int = Field(ge=1)
    source: Literal["file", "url"]
    openapi_version: str
    operation_count: int = Field(ge=0)
    imported_at: datetime
    source_url: str | None
    file_name: str | None
    format: Literal["json", "yaml"]
    api_title: str | None
    sha256: str
    is_current: bool
    warnings: list[Warning]
    changes: ContractChanges | None


class ContractPage(ContractModel):
    items: list[ContractVersionSummary]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)


class Parameter(ContractModel):
    name: str
    location: Literal["path", "query", "header", "cookie"]
    required: bool
    type: str | None


class RequestBody(ContractModel):
    required: bool
    content_types: list[str]


class DeclaredSecurity(ContractModel):
    scheme: str
    type: Literal["http_bearer", "http_basic", "api_key", "oauth2", "openid_connect", "other"]


# RF-35. The same component is the input of PATCH .../operations/{operation_id} (task 2.6).
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=SINGLE_LINE)]


class ResourceParameter(ContractModel):
    name: ShortText
    resource_type: ShortText


class Operation(ContractModel):
    id: UUID
    method: HttpMethod
    path: str
    operation_id: str | None
    summary: str | None
    tags: list[str]
    parameters: list[Parameter]
    body: RequestBody | None
    security: list[DeclaredSecurity]
    retired_at: datetime | None
    suggested_policy: Policy | None
    policy: Policy | None
    owner_field: str | None
    confirmed_at: datetime | None
    modified_at: datetime | None
    resource_parameters: list[ResourceParameter]
    is_login_candidate: bool


class OperationPage(ContractModel):
    items: list[Operation]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
