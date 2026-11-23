"""AES-256-GCM of the identities' credentials (ADR-007; RN-11, RF-31) and its keys in Settings."""

import base64
import os
import uuid

import pytest
from pydantic import SecretStr, ValidationError

from hindama.config import Settings
from hindama.core.credentials import (
    HEADER_BYTES,
    TAG_BYTES,
    Credential,
    CredentialCipher,
    CredentialUnreadableError,
)
from tests.conftest import make_settings

KEY_1 = os.urandom(32)
KEY_2 = os.urandom(32)
TOKEN = Credential(token="eyJhbGciOiJIUzI1NiJ9.secreto-largo-9f2a")
ID = uuid.uuid4()


def cipher(current: int = 1, **keys: bytes) -> CredentialCipher:
    loaded = {int(v.removeprefix("v")): k for v, k in keys.items()} or {1: KEY_1}
    return CredentialCipher(loaded, current)


def test_a_credential_comes_back_as_it_went_in() -> None:
    c = cipher()
    login = Credential(username="ana@ejemplo.com", password="contraseña con espacios")
    for credential in (TOKEN, login, Credential(value="abc")):
        assert c.decrypt(ID, c.encrypt(ID, credential)) == credential


def test_the_stored_value_is_version_nonce_ciphertext_and_tag() -> None:
    stored = cipher().encrypt(ID, TOKEN)
    assert stored[0] == 1
    assert len(stored) == HEADER_BYTES + len(TOKEN.to_bytes()) + TAG_BYTES
    assert b"secreto" not in stored


def test_each_encryption_uses_a_new_nonce() -> None:
    c = cipher()
    first, second = c.encrypt(ID, TOKEN), c.encrypt(ID, TOKEN)
    assert first[1:HEADER_BYTES] != second[1:HEADER_BYTES]
    assert first != second


def test_a_ciphertext_moved_to_another_row_does_not_decrypt() -> None:
    """The identity id is the associated data: copying the column to another identity fails."""
    c = cipher()
    stored = c.encrypt(ID, TOKEN)
    with pytest.raises(CredentialUnreadableError):
        c.decrypt(uuid.uuid4(), stored)


@pytest.mark.parametrize("position", [0 + 1, HEADER_BYTES, -1])
def test_any_altered_byte_is_detected(position: int) -> None:
    c = cipher()
    stored = bytearray(c.encrypt(ID, TOKEN))
    stored[position] ^= 0x01
    with pytest.raises(CredentialUnreadableError):
        c.decrypt(ID, bytes(stored))


@pytest.mark.parametrize("stored", [b"", b"\x01", b"\x01" + b"\x00" * (HEADER_BYTES + 15)])
def test_a_truncated_value_is_unreadable(stored: bytes) -> None:
    with pytest.raises(CredentialUnreadableError):
        cipher().decrypt(ID, stored)


def test_a_wrong_key_cannot_read_it() -> None:
    stored = cipher().encrypt(ID, TOKEN)
    with pytest.raises(CredentialUnreadableError):
        CredentialCipher({1: KEY_2}, 1).decrypt(ID, stored)


def test_an_unloaded_key_version_is_unreadable() -> None:
    stored = cipher(2, v1=KEY_1, v2=KEY_2).encrypt(ID, TOKEN)
    with pytest.raises(CredentialUnreadableError):
        cipher().decrypt(ID, stored)


def test_rotation_keeps_old_rows_readable_and_writes_with_the_new_key() -> None:
    old = cipher().encrypt(ID, TOKEN)
    rotated = cipher(2, v1=KEY_1, v2=KEY_2)
    assert rotated.decrypt(ID, old) == TOKEN
    fresh = rotated.encrypt(ID, TOKEN)
    assert CredentialCipher.key_version_of(fresh) == 2
    assert rotated.decrypt(ID, fresh) == TOKEN


def test_relabelling_the_key_version_does_not_decrypt() -> None:
    """The version is in the associated data too: changing the byte is tampering."""
    both = CredentialCipher({1: KEY_1, 2: KEY_1}, 1)  # same key under two versions
    stored = bytearray(both.encrypt(ID, TOKEN))
    stored[0] = 2
    with pytest.raises(CredentialUnreadableError):
        both.decrypt(ID, bytes(stored))


@pytest.mark.parametrize(
    ("keys", "current"),
    [({1: KEY_1}, 2), ({1: b"short"}, 1), ({0: KEY_1}, 0), ({256: KEY_1}, 256)],
)
def test_bad_keys_are_refused(keys: dict[int, bytes], current: int) -> None:
    with pytest.raises(ValueError, match="key"):
        CredentialCipher(keys, current)


def test_nothing_secret_shows_in_reprs() -> None:
    assert "secreto" not in repr(TOKEN)
    assert repr(TOKEN) == "Credential(token: ***)"
    assert KEY_1.hex() not in repr(cipher())
    assert "versions=[1]" in repr(cipher())


def test_the_suffix_never_shows_a_password_nor_most_of_a_short_secret() -> None:
    assert TOKEN.suffix() == "9f2a"
    assert Credential(username="ana@ejemplo.com", password="secreta").suffix() == ".com"
    assert Credential(value="1234567").suffix() == ""  # 4 of 7 would be more than half
    assert Credential(value="12345678").suffix() == "5678"


# ------------------------------------------------------------------ settings


def with_keys(keys: object, version: int = 1) -> Settings:
    base = make_settings("postgresql+asyncpg://test:test@localhost:1/unused")
    data = base.model_dump()
    data.update(credential_keys=keys, credential_key_version=version)
    return Settings(**data)


def b64(key: bytes) -> str:
    return base64.b64encode(key).decode()


def test_settings_build_the_cipher() -> None:
    settings = with_keys({"1": b64(KEY_1), "2": b64(KEY_2)}, version=2)
    c = settings.credential_cipher()
    assert c.current_version == 2
    assert c.decrypt(ID, CredentialCipher({1: KEY_1}, 1).encrypt(ID, TOKEN)) == TOKEN


@pytest.mark.parametrize(
    ("keys", "version", "reason"),
    [
        ({"1": "no es base64!"}, 1, "base64"),
        ({"1": b64(b"x" * 16)}, 1, "32 bytes"),
        ({"1": b64(KEY_1)}, 2, "not among"),
        ({"300": b64(KEY_1)}, 1, "1 to 255"),
    ],
)
def test_settings_refuse_bad_keys_without_echoing_them(
    keys: dict[str, str], version: int, reason: str
) -> None:
    with pytest.raises(ValidationError) as error:
        with_keys(keys, version)
    assert reason in str(error.value)
    for key in keys.values():
        assert key not in str(error.value)
    assert "input_value" not in str(error.value)


def test_settings_need_at_least_one_key() -> None:
    with pytest.raises(ValidationError):
        with_keys({})


def test_the_key_is_a_secret_in_the_settings_repr() -> None:
    settings = with_keys({"1": b64(KEY_1)})
    assert b64(KEY_1) not in repr(settings)
    assert isinstance(settings.credential_keys[1], SecretStr)
