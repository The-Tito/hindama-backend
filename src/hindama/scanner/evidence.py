"""Evidence of a finding (RF-66, RF-67, RN-11): the request and the response that reproduce it.

Built in memory by the scanner and stored as is: credentials are masked here, before anything is
written. The secrets of the identity are also searched in the response, because an API may echo
a token back.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from hindama.models.base import MAX_EVIDENCE_BYTES

MAX_BODY_BYTES = 10 * 1024  # RF-67
MAX_HEADERS = 50
MAX_HEADER_VALUE = 500
MASK = "****"
# Headers that carry credentials whatever the identity: always masked.
SENSITIVE_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
)


def mask(value: str) -> str:
    """RF-31: only the last 4 characters, and none of a value too short to hide the rest."""
    return MASK + value[-4:] if len(value) > 8 else MASK


@dataclass(frozen=True, slots=True)
class Exchange:
    """One request and its response, as sent and received. Holds secrets: never log it."""

    method: str
    url: str
    request_headers: Mapping[str, str]
    status_code: int
    response_headers: Iterable[tuple[str, str]]
    body: bytes

    def __repr__(self) -> str:
        return f"Exchange({self.method} {self.url} -> {self.status_code})"


class Masker:
    """Hides the secrets of a run: header names that carry them and their values anywhere."""

    def __init__(self, secrets: Iterable[str] = (), header_names: Iterable[str] = ()) -> None:
        self._secrets = {s for s in secrets if s}
        self._headers = SENSITIVE_HEADERS | {name.lower() for name in header_names}

    def add(self, secret: str) -> None:
        """A secret learnt during the run, such as the token of a login."""
        if secret:
            self._secrets.add(secret)

    def text(self, value: str) -> str:
        # Longest first: a token that contains another secret is replaced whole.
        for secret in sorted(self._secrets, key=len, reverse=True):
            if secret in value:
                value = value.replace(secret, mask(secret))
        return value

    def headers(self, headers: Iterable[tuple[str, str]]) -> dict[str, str]:
        result: dict[str, str] = {}
        for name, value in headers:
            if len(result) >= MAX_HEADERS:
                break
            key = name.lower()
            shown = mask(value) if key in self._headers else self.text(value)
            result[key] = shown[:MAX_HEADER_VALUE]
        return result

    def evidence(self, exchange: Exchange, **context: Any) -> dict[str, Any]:
        """The stored evidence, under the size the database accepts (`evidence_size`)."""
        body_limit = MAX_BODY_BYTES
        while True:
            body = exchange.body[:body_limit]
            evidence = {
                "request": {
                    "method": exchange.method,
                    "url": self.text(exchange.url),
                    "headers": self.headers(exchange.request_headers.items()),
                },
                "response": {
                    "status_code": exchange.status_code,
                    "headers": self.headers(exchange.response_headers),
                    "body": self.text(body.decode("utf-8", errors="replace")),
                    "body_truncated": len(exchange.body) > len(body),
                },
                **context,
            }
            # Escaping can grow a body several times (`\u0000`): shrink it until it fits.
            if len(json.dumps(evidence).encode()) <= MAX_EVIDENCE_BYTES or body_limit == 0:
                return evidence
            body_limit //= 2
