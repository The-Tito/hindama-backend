"""Test identities' credentials, encrypted at rest with AES-256-GCM (ADR-007; RN-11, RF-31, RNF-06).

Stored value: `key_version (1 byte) || nonce (12 bytes) || ciphertext || tag (16 bytes)`. The
associated data is the identity's id plus the key version, so a ciphertext copied to another row,
or relabelled with another key version, fails authentication instead of decrypting.

The master keys come from the environment (SSM Parameter Store in production) and never touch the
database. Several versions may be loaded at once: new credentials use the current one, and older
rows stay readable until a rotation script re-encrypts them.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, fields
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
HEADER_BYTES = 1 + NONCE_BYTES
SUFFIX_LENGTH = 4
# A secret shorter than this shows no suffix: 4 characters would reveal half of it or more.
MIN_SECRET_FOR_SUFFIX = 8


@dataclass(frozen=True, slots=True, repr=False)
class Credential:
    """The plain credential, only in memory. Its repr never shows the values (tracebacks, logs).

    `login`: username and password; `bearer`: token; `cookie` and `header`: value.
    """

    username: str | None = None
    password: str | None = None
    token: str | None = None
    value: str | None = None

    def __repr__(self) -> str:
        present = [f.name for f in fields(self) if getattr(self, f.name) is not None]
        return f"Credential({', '.join(present)}: ***)"

    def to_bytes(self) -> bytes:
        data = {f.name: getattr(self, f.name) for f in fields(self)}
        return json.dumps({k: v for k, v in data.items() if v is not None}).encode()

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Credential":
        data = json.loads(raw)
        return cls(**{f.name: data.get(f.name) for f in fields(cls)})

    def suffix(self) -> str:
        """RF-31. In `login`, from the username: the password is never shown, not even in part."""
        if self.username is not None:
            return self.username[-SUFFIX_LENGTH:]
        secret = self.token if self.token is not None else self.value
        if secret is None or len(secret) < MIN_SECRET_FOR_SUFFIX:
            return ""
        return secret[-SUFFIX_LENGTH:]


class CredentialUnreadableError(Exception):
    """Tampered ciphertext, a row id that does not match, or a key version that is not loaded.

    Deliberately without detail: which check failed is not something to tell anyone.
    """

    def __init__(self) -> None:
        super().__init__("the credential cannot be decrypted")


class CredentialCipher:
    def __init__(self, keys: Mapping[int, bytes], current_version: int) -> None:
        if current_version not in keys:
            raise ValueError("the current key version is not among the keys")
        for version, key in keys.items():
            if not 1 <= version <= 255:
                raise ValueError("key versions go from 1 to 255")
            if len(key) != KEY_BYTES:
                raise ValueError(f"key version {version} is not {KEY_BYTES} bytes long")
        self._keys = {version: AESGCM(key) for version, key in keys.items()}
        self.current_version = current_version

    def __repr__(self) -> str:
        return f"CredentialCipher(versions={sorted(self._keys)}, current={self.current_version})"

    @staticmethod
    def _associated_data(identity_id: UUID, version: int) -> bytes:
        return identity_id.bytes + bytes([version])

    def encrypt(self, identity_id: UUID, credential: Credential) -> bytes:
        version = self.current_version
        nonce = os.urandom(NONCE_BYTES)  # random 96 bits: one per encryption, never reused
        sealed = self._keys[version].encrypt(
            nonce, credential.to_bytes(), self._associated_data(identity_id, version)
        )
        return bytes([version]) + nonce + sealed

    def decrypt(self, identity_id: UUID, stored: bytes) -> Credential:
        if len(stored) < HEADER_BYTES + TAG_BYTES:
            raise CredentialUnreadableError()
        version = stored[0]
        key = self._keys.get(version)
        if key is None:
            raise CredentialUnreadableError()
        nonce, sealed = stored[1:HEADER_BYTES], stored[HEADER_BYTES:]
        try:
            raw = key.decrypt(nonce, sealed, self._associated_data(identity_id, version))
        except InvalidTag:
            raise CredentialUnreadableError() from None
        return Credential.from_bytes(raw)

    @staticmethod
    def key_version_of(stored: bytes) -> int:
        return stored[0]
