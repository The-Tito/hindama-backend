"""Per-request identifier (`X-Request-Id`), available anywhere through a context variable."""

import re
from contextvars import ContextVar

from uuid6 import uuid7

REQUEST_ID_HEADER = "X-Request-Id"

# Accept the id sent by Next.js only if it is short and harmless: it ends up in logs and responses.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def new_request_id() -> str:
    return str(uuid7())


def accept_or_generate(incoming: str | None) -> str:
    """Keep a well-formed incoming id; otherwise generate a new one (convenciones.md, section 3)."""
    if incoming and _VALID_REQUEST_ID.fullmatch(incoming):
        return incoming
    return new_request_id()


def get_request_id() -> str | None:
    return _request_id.get()


def set_request_id(value: str | None) -> None:
    _request_id.set(value)
