"""Schemas of `/me` (components `Me`, `TermsStatus`, `TermsAcceptance`)."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import Field, StringConstraints

from hindama.core.auth import Role
from hindama.schemas.common import SINGLE_LINE, ContractModel

# Only documented as an email: the value comes from Cognito, which already validated it.
Email = Annotated[str, Field(json_schema_extra={"format": "email"})]


class TermsStatus(ContractModel):
    current_version: str
    accepted_version: str | None
    accepted_at: datetime | None
    acceptance_required: bool


class Me(ContractModel):
    id: UUID
    name: str
    email: Email
    role: Role
    terms: TermsStatus


class TermsAcceptance(ContractModel):
    version: Annotated[str, StringConstraints(max_length=50, pattern=SINGLE_LINE)]
