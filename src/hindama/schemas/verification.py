"""Schemas of `/projects/{project_id}/verification` (components `Verification`,
`VerificationRequest` and `VerificationProblem`)."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from hindama.models.enums import VerificationMethod, VerificationStatus
from hindama.schemas.common import ContractModel, FieldError


class VerificationRequest(ContractModel):
    method: VerificationMethod


class FileInstructions(ContractModel):
    url: str
    content: str


class DnsInstructions(ContractModel):
    name: str
    type: Literal["TXT"]
    value: str


class Verification(ContractModel):
    status: VerificationStatus
    host: str
    code: str
    method: VerificationMethod | None
    verified_at: datetime | None
    file: FileInstructions
    dns: DnsInstructions


VerificationErrorCode = Literal[
    "verification.file_not_found",
    "verification.content_mismatch",
    "verification.txt_missing",
    "verification.connection_error",
    "verification.destination_not_allowed",
]


class VerificationProblem(ContractModel):
    """`Problem` with `found`: what the check obtained, as untrusted text. Documentation only; the
    body is built by `api.problems.problem_response` like every other error."""

    type: str
    title: str
    status: int
    detail: str
    code: VerificationErrorCode
    request_id: str
    errors: list[FieldError]
    found: Annotated[str, Field(max_length=200)] | None
