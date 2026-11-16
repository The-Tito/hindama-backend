"""Schemas of `/identities` (components `IdentityCreate`, `IdentityUpdate`, `Identity`,
`Credential`, `IdentityTest`...). The credential is write-only: no response model has a field that
holds it (RN-11, RF-31)."""

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import MISSING, Field, StringConstraints, WithJsonSchema, field_validator

from hindama.models.enums import AuthType, IdentityRole, IdentityStatus
from hindama.schemas.common import SINGLE_LINE, ContractModel, Warning
from hindama.schemas.contracts import OperationRef
from hindama.schemas.projects import Name

Secret = Annotated[str, StringConstraints(min_length=1, max_length=4096, pattern=SINGLE_LINE)]
RoleLabel = Annotated[str, StringConstraints(max_length=100, pattern=SINGLE_LINE)]
# An HTTP token (RFC 9110 5.6.2): what a cookie or header name may contain.
FieldName = Annotated[
    str, StringConstraints(min_length=1, max_length=100, pattern=r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
]
SettableAuthType = Literal["login", "bearer", "cookie", "header"]


class LoginCredential(ContractModel):
    username: Secret
    password: Secret


class TokenCredential(ContractModel):
    token: Secret


class ValueCredential(ContractModel):
    value: Secret


def _one_of(schema: dict[str, Any]) -> None:
    """Pydantic writes a plain union as `anyOf`; the three shapes exclude each other (`oneOf`)."""
    schema["oneOf"] = schema.pop("anyOf")
    schema["writeOnly"] = True


Credential = Annotated[
    LoginCredential | TokenCredential | ValueCredential,
    Field(json_schema_extra=_one_of),
]


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


class IdentityCreate(ContractModel):
    name: Name
    role: IdentityRole
    role_label: RoleLabel | None = None
    auth_type: SettableAuthType
    credential: Credential
    field_name: FieldName | None = None
    login_operation_id: UUID | None = None

    _role_label = field_validator("role_label")(_blank_to_none)


class IdentityUpdate(ContractModel):
    """Only the fields sent change. `MISSING` keeps "not sent" apart from `null`."""

    name: Name | MISSING = MISSING
    role: IdentityRole | MISSING = MISSING
    role_label: RoleLabel | MISSING | None = MISSING
    auth_type: SettableAuthType | MISSING = MISSING
    credential: Credential | MISSING = MISSING
    field_name: FieldName | MISSING | None = MISSING
    login_operation_id: UUID | MISSING | None = MISSING

    _role_label = field_validator("role_label")(_blank_to_none)


class Identity(ContractModel):
    id: UUID
    name: str
    role: IdentityRole
    role_label: str | None
    auth_type: AuthType
    credential_suffix: str | None = Field(max_length=4)
    field_name: str | None
    login_operation: OperationRef | None
    status: IdentityStatus
    last_tested_at: datetime | None
    last_test_status_code: int | None
    resource_count: int = Field(ge=0)
    warnings: list[Warning]
    created_at: datetime


class IdentityPage(ContractModel):
    items: list[Identity]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)


class IdentityTestRequest(ContractModel):
    operation_id: UUID | None = None


TestFailure = Literal["rejected", "login_failed", "connection_error", "destination_not_allowed"]


class IdentityTest(ContractModel):
    succeeded: bool
    status_code: int | None
    # The contract lists `null` among the values: same meaning as Pydantic's `X | None`.
    failure: Annotated[
        TestFailure | None,
        WithJsonSchema(
            {
                "type": ["string", "null"],
                "enum": [
                    "rejected",
                    "login_failed",
                    "connection_error",
                    "destination_not_allowed",
                    None,
                ],
            }
        ),
    ]
    operation: OperationRef
    tested_at: datetime
