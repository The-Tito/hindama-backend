"""Building blocks of the audit log (core/audit.py, services/audit.py; RF-82 to RF-84, ADR-015)."""

import asyncio
import base64
import hashlib
import hmac
import os

import pytest
from pydantic import SecretStr, ValidationError

from hindama.config import Settings
from hindama.core.audit import HostHasher, client_ip, collect_blocks, note_block
from hindama.core.safe_http import BlockReason, DestinationBlockedError, SafeHttpClient
from tests.conftest import make_settings
from tests.servers import ScriptedResolver

KEY_1 = os.urandom(32)
KEY_2 = os.urandom(32)


# ------------------------------------------------------------------ the host's HMAC (RF-83)


def test_the_digest_is_the_hmac_sha256_of_the_host_with_the_current_key() -> None:
    hasher = HostHasher({1: KEY_1, 2: KEY_2}, current_version=2)

    digest = hasher.digest("api.ejemplo.com")

    assert digest.version == 2
    assert digest.value == hmac.new(KEY_2, b"api.ejemplo.com", hashlib.sha256).digest()
    assert hasher.digest("api.ejemplo.com") == digest  # deterministic: the search relies on it
    assert hasher.digest("otra.ejemplo.com") != digest


def test_a_search_covers_every_loaded_version() -> None:
    hasher = HostHasher({1: KEY_1, 2: KEY_2}, current_version=2)
    old = HostHasher({1: KEY_1}, current_version=1).digest("api.ejemplo.com")

    assert old in hasher.candidates("api.ejemplo.com")
    assert {c.version for c in hasher.candidates("api.ejemplo.com")} == {1, 2}


def test_the_hasher_never_shows_its_keys() -> None:
    hasher = HostHasher({1: KEY_1}, current_version=1)

    assert KEY_1.hex() not in repr(hasher)
    assert repr(KEY_1) not in repr(hasher)


def test_the_current_version_must_be_loaded() -> None:
    with pytest.raises(ValueError, match="not loaded"):
        HostHasher({1: KEY_1}, current_version=2)


# ------------------------------------------------------------------ settings


def with_audit_keys(keys: object, version: int = 1) -> Settings:
    data = make_settings("postgresql+asyncpg://test:test@localhost:1/unused").model_dump()
    data.update(audit_hmac_keys=keys, audit_hmac_key_version=version)
    return Settings(**data)


def b64(key: bytes) -> str:
    return base64.b64encode(key).decode()


def test_settings_build_the_hasher() -> None:
    settings = with_audit_keys({"1": b64(KEY_1), "2": b64(KEY_2)}, version=2)

    hasher = settings.host_hasher()

    assert hasher.digest("x.test") == HostHasher({2: KEY_2}, 2).digest("x.test")
    assert isinstance(settings.audit_hmac_keys[1], SecretStr)
    assert b64(KEY_1) not in repr(settings)


@pytest.mark.parametrize(
    ("keys", "version", "reason"),
    [
        ({"1": "no es base64!"}, 1, "base64"),
        ({"1": b64(b"x" * 16)}, 1, "32 bytes"),
        ({"1": b64(KEY_1)}, 2, "not among"),
        ({}, 1, "at least 1"),
    ],
)
def test_settings_refuse_bad_audit_keys_without_echoing_them(
    keys: dict[str, str], version: int, reason: str
) -> None:
    with pytest.raises(ValidationError) as error:
        with_audit_keys(keys, version)

    assert reason in str(error.value)
    for key in keys.values():
        assert key not in str(error.value)


# ------------------------------------------------------------------ the browser's IP (RF-82)


@pytest.mark.parametrize(
    ("given", "kept"),
    [
        ("203.0.113.25", "203.0.113.25"),
        ("  203.0.113.25 ", "203.0.113.25"),
        ("2001:DB8:0:0::1", "2001:db8::1"),
        ("::ffff:203.0.113.25", "::ffff:203.0.113.25"),
        (None, None),
        ("", None),
        ("no es una ip", None),
        ("203.0.113.25, 10.0.0.1", None),  # a forwarded list is not an address
        ("203.0.113.256", None),
        ("fe80::1%eth0", None),  # a zone means nothing outside one machine
        ("1" * 100, None),
    ],
)
def test_client_ip(given: str | None, kept: str | None) -> None:
    assert client_ip(given) == kept


# ------------------------------------------------------------------ blocked destinations


def test_a_block_outside_a_collector_goes_nowhere() -> None:
    note_block("address_not_allowed", "api.ejemplo.com")  # only the process log has it

    with collect_blocks() as collector:
        pass

    assert collector.blocks == []


def test_the_collector_keeps_one_entry_per_reason_and_host() -> None:
    with collect_blocks() as collector:
        for _ in range(3):
            note_block("address_not_allowed", "api.ejemplo.com")
        note_block("host_mismatch", "api.ejemplo.com")
        note_block("address_not_allowed", "otra.ejemplo.com")

    assert [(b.reason, b.host) for b in collector.distinct()] == [
        ("address_not_allowed", "api.ejemplo.com"),
        ("host_mismatch", "api.ejemplo.com"),
        ("address_not_allowed", "otra.ejemplo.com"),
    ]


async def test_tasks_started_inside_the_collector_note_into_it() -> None:
    """The scanner runs its requests in tasks: they inherit the collector."""
    with collect_blocks() as collector:
        async with asyncio.TaskGroup() as group:
            for host in ("a.test", "b.test"):
                group.create_task(_note(host))

    assert sorted(b.host for b in collector.blocks) == ["a.test", "b.test"]


async def _note(host: str) -> None:
    note_block("address_not_allowed", host)


async def test_the_ssrf_guard_notes_its_blocks() -> None:
    client = SafeHttpClient("api.ejemplo.com", resolver=ScriptedResolver(["10.0.0.9"]))

    with collect_blocks() as collector, pytest.raises(DestinationBlockedError):
        async with client:
            await client.get("https://api.ejemplo.com/orders")

    assert [(b.reason, b.host) for b in collector.blocks] == [
        (BlockReason.ADDRESS_NOT_ALLOWED.value, "api.ejemplo.com")
    ]


async def test_an_unresolved_name_is_not_noted_as_a_block() -> None:
    class Unresolved:
        async def resolve(self, host: str) -> list[object]:
            return []

    client = SafeHttpClient("no-existe.ejemplo.com", resolver=Unresolved())  # type: ignore[arg-type]

    with collect_blocks() as collector, pytest.raises(DestinationBlockedError) as error:
        async with client:
            await client.get("https://no-existe.ejemplo.com/")

    assert error.value.reason == BlockReason.UNRESOLVED
    assert collector.blocks == []
