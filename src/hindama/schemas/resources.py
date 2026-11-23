"""Schemas of `/resources` (components `ResourceCreate`, `ResourceUpdate`, `Resource`,
`ResourcePage`, `ResourceDiscoveryRequest`, `ResourceDiscovery`). The values come from the analyst
or from their own API: objects of that API (F-06)."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import MISSING, Field, StringConstraints, WithJsonSchema, field_validator

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


class ResourceDiscoveryRequest(ContractModel):
    # A list, not a set: an error names its position (`identity_ids.N`). Absent: all of them.
    identity_ids: (
        Annotated[
            list[UUID], Field(min_length=1, max_length=20, json_schema_extra={"uniqueItems": True})
        ]
        | MISSING
    ) = MISSING

    @field_validator("identity_ids")
    @classmethod
    def _unique(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("identity_ids no admite repetidos")
        return value


FAILURES = (
    "rejected",
    "login_failed",
    "connection_error",
    "destination_not_allowed",
    "not_attempted",
)
DiscoveryFailure = Literal[
    "rejected", "login_failed", "connection_error", "destination_not_allowed", "not_attempted"
]


class DiscoveryIdentityResult(ContractModel):
    identity_id: UUID
    found: int = Field(ge=0)
    created: int = Field(ge=0)
    owned_by_other: int = Field(ge=0)
    # The contract lists `null` among the values: same meaning as Pydantic's `X | None`.
    failure: Annotated[
        DiscoveryFailure | None,
        WithJsonSchema({"type": ["string", "null"], "enum": [*FAILURES, None]}),
    ]


class ResourceDiscovery(ContractModel):
    created: list[Resource]
    identities: list[DiscoveryIdentityResult]
    requests_sent: int = Field(ge=0)
    truncated: bool
