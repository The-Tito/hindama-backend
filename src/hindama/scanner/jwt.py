"""Forged variants of an identity's own JWT (RF-54; catalog, section 6.1).

Nothing here verifies or signs: the scanner never holds the key of the analyst's API. It only
changes the token the identity already has, to see whether the API notices.
"""

import base64
import binascii
import hashlib
import json
from typing import Any


def _decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def header(token: str) -> dict[str, Any] | None:
    """The JOSE header of a compact JWS, or None if the token is not one."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None
    try:
        decoded = json.loads(_decode(parts[0]))
        _decode(parts[1])
    except (binascii.Error, ValueError, RecursionError):
        return None
    if not isinstance(decoded, dict) or not isinstance(decoded.get("alg"), str):
        return None
    return decoded


def is_jwt(token: str) -> bool:
    return header(token) is not None


def tampered_signature(token: str) -> str:
    """Same header and claims, another signature of the same length."""
    head, claims, signature = token.split(".")
    original = _decode(signature) if signature else b""
    forged = hashlib.sha256(b"hindama" + original).digest()
    forged = (forged * (len(original) // len(forged) + 1))[: max(len(original), 1)]
    if forged == original:  # pragma: no cover - a collision of SHA-256
        forged = bytes(b ^ 0xFF for b in forged)
    return f"{head}.{claims}.{_encode(forged)}"


def alg_none(token: str) -> str:
    """The same claims with `"alg": "none"` and no signature: accepted only by a broken API."""
    decoded = header(token) or {}
    _, claims, _ = token.split(".")
    forged = {**decoded, "alg": "none"}
    return f"{_encode(json.dumps(forged, separators=(',', ':')).encode())}.{claims}."
