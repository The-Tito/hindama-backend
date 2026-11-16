"""Schemas of `/resources` (components `ResourceCreate`, `ResourceUpdate`, `Resource`,
`ResourcePage`). The values come from the analyst: objects of their own API (F-06)."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import MISSING, Field, StringConstraints

from hindama.schemas.common import SINGLE_LINE, ContractModel

ResourceType = Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=SINGLE_LINE)]
ResourceValue = Annotated[str, StringConstraints(min_length=1, max_length=500, pattern=SINGLE_LINE)]


class ResourceCreate(ContractModel):
    identity_id: UUID
    resource_type: ResourceType
    value: ResourceValue


class ResourceUpdate(ContractModel):
    identity_id: UUID | MISSING = MISSING
    resource_type: ResourceType | MISSING = MISSING
    value: ResourceValue | MISSING = MISSING
    confirmed: bool | MISSING = MISSING


class Resource(ContractModel):
    id: UUID
    identity_id: UUID
    resource_type: str
    value: str
    source: Literal["discovered", "manual"]
    confirmed: bool
    created_at: datetime


class ResourcePage(ContractModel):
    items: list[Resource]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
