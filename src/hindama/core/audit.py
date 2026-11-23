"""Building blocks of the audit log (F-14; RF-81 to RF-84; ADR-015).

- `HostHasher`: the log stores the HMAC-SHA256 of a host, never the host (RF-83). The keys are
  versioned like the credential keys: new entries use the current version, and a search by host
  computes the HMAC with every loaded version (RF-84).
- `client_ip`: the browser's IP that the frontend forwards in `X-Hindama-Client-IP` (RF-82). Only a
  valid IPv4 or IPv6 address is kept; trust comes from the network (only the frontend reaches the
  API), and the value never authorizes anything.
- `collect_blocks`: the SSRF guard notes every blocked destination in the current context, so the
  endpoint or the run that caused it can audit it, even when the request then fails (RF-50).
"""

import hashlib
import hmac
import ipaddress
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

# Longest textual IPv6 with an IPv4 tail and a zone: anything longer is not an address.
_MAX_IP_LENGTH = 64


@dataclass(frozen=True, slots=True)
class HostDigest:
    value: bytes
    version: int


class HostHasher:
    """HMAC-SHA256 of normalized hosts (lowercase, IDNA, no port), by key version."""

    def __init__(self, keys: Mapping[int, bytes], current_version: int) -> None:
        if current_version not in keys:
            raise ValueError("the current audit key version is not loaded")
        self._keys = dict(keys)
        self._current = current_version

    def digest(self, host: str) -> HostDigest:
        return HostDigest(self._hmac(self._keys[self._current], host), self._current)

    def candidates(self, host: str) -> list[HostDigest]:
        """The digest of `host` under every loaded version, to search old entries too."""
        return [HostDigest(self._hmac(key, host), version) for version, key in self._keys.items()]

    @staticmethod
    def _hmac(key: bytes, host: str) -> bytes:
        return hmac.new(key, host.encode("ascii", "strict"), hashlib.sha256).digest()

    def __repr__(self) -> str:  # never the keys
        return f"HostHasher(versions={sorted(self._keys)}, current={self._current})"


def client_ip(raw: str | None) -> str | None:
    """The IP the frontend reported, normalized, or None if missing or not an address."""
    if raw is None:
        return None
    value = raw.strip()
    if not value or len(value) > _MAX_IP_LENGTH:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        return None  # a zone only makes sense inside one machine
    return str(address)


# ---------------------------------------------------------------------------- blocked destinations


@dataclass(frozen=True, slots=True)
class Block:
    reason: str  # safe_http.BlockReason
    host: str  # the host the client was bound to: the project's, or a contract URL's


@dataclass(slots=True)
class BlockCollector:
    blocks: list[Block] = field(default_factory=list)

    def distinct(self) -> list[Block]:
        """One entry per reason and host: a run may hit the same block hundreds of times."""
        return list(dict.fromkeys(self.blocks))


_collector: ContextVar[BlockCollector | None] = ContextVar("audit_block_collector", default=None)


@contextmanager
def collect_blocks() -> Iterator[BlockCollector]:
    """Blocks noted inside this context (and the tasks it starts) land in the collector."""
    collector = BlockCollector()
    token = _collector.set(collector)
    try:
        yield collector
    finally:
        _collector.reset(token)


def note_block(reason: str, host: str) -> None:
    """Called by the SSRF guard. Outside `collect_blocks` it only reaches the process log."""
    collector = _collector.get()
    if collector is not None:
        collector.blocks.append(Block(reason, host))
