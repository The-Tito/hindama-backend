"""Structured logging with secret masking (RN-11, RNF-06).

Every log line goes through `mask_secrets` before it is rendered, so a credential passed to a
logger by mistake is replaced with `***` instead of reaching CloudWatch.
"""

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog

from hindama.core.request_context import get_request_id

MASK = "***"

# Keys whose values are always secret, whatever their content.
_SECRET_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|authorization|cookie|credential|api[_-]?key|private[_-]?key"
    r"|database_url|dsn)",
    re.IGNORECASE,
)
# Secrets embedded inside free text.
_SECRET_IN_TEXT = (
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), r"\1 " + MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), MASK),  # JWT
    (re.compile(r"(?i)(://[^:/@\s]+:)[^@\s]+@"), r"\1" + MASK + "@"),  # password in a URL
    # key=value or key: value pairs whose key looks secret, e.g. inside an exception message
    (
        re.compile(
            r"(?i)\b((?:pass(?:word|wd)?|secret|token|api[_-]?key|credential)\w*[\"']?\s*[=:]\s*)"
            r"[\"']?[^\s\"',;&]+"
        ),
        r"\1" + MASK,
    ),
)


def mask_text(value: str) -> str:
    for pattern, replacement in _SECRET_IN_TEXT:
        value = pattern.sub(replacement, value)
    return value


def mask_value(key: str | None, value: Any) -> Any:
    if key is not None and _SECRET_KEY.search(key):
        return MASK
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, Mapping):
        return {k: mask_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [mask_value(None, v) for v in value]
    return value


def mask_secrets(_: Any, __: str, event_dict: MutableMapping[str, Any]) -> dict[str, Any]:
    """structlog processor: masks secret keys and secret-looking text in every field."""
    return {k: mask_value(k if k != "event" else None, v) for k, v in event_dict.items()}


def add_request_id(
    _: Any, __: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    request_id = get_request_id()
    if request_id is not None:
        event_dict.setdefault("request_id", request_id)
    return event_dict


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    renderer: Any = (
        structlog.processors.JSONRenderer()
        if fmt == "json"
        else structlog.dev.ConsoleRenderer(colors=False)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            add_request_id,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            mask_secrets,  # last before rendering: also covers formatted tracebacks
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
