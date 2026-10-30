"""Schemas shared by every endpoint (components `Problem`, `FieldError`, `Warning`, `Health`)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ContractModel(BaseModel):
    """Base of every response schema: closed, like the contract (additionalProperties: false)."""

    model_config = ConfigDict(extra="forbid")


class FieldError(ContractModel):
    field: str | None
    code: str
    message: str


class Problem(ContractModel):
    """RFC 9457 Problem Details with Hindama's extensions (convenciones.md, section 8)."""

    type: str
    title: str
    status: int
    detail: str
    code: str
    request_id: str
    errors: list[FieldError]


class Warning(ContractModel):  # name fixed by the contract; shadows the builtin
    code: str
    message: str
    location: str | None


class Health(ContractModel):
    status: Literal["ok"]
