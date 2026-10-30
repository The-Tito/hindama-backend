"""Secrets never reach the logs (RN-11)."""

import json

import pytest
import structlog

from hindama.core.logging import MASK, configure_logging, mask_secrets, mask_text


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Bearer abc.def-ghi", "abc.def-ghi"),
        ("basic dXNlcjpwYXNz in header", "dXNlcjpwYXNz"),
        ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_123 leaked", "eyJhbGciOiJIUzI1NiJ9"),
        ("postgresql+asyncpg://hindama_api:hunter2@db:5432/hindama", "hunter2"),
        ("login failed: password=hunter2 for user a", "hunter2"),
        ('{"api_key": "k-998877"}', "k-998877"),
    ],
)
def test_masks_secrets_inside_text(text: str, secret: str) -> None:
    masked = mask_text(text)

    assert secret not in masked
    assert MASK in masked


def test_masks_values_of_secret_keys_at_any_depth() -> None:
    event = mask_secrets(
        None,
        "info",
        {
            "event": "identity_tested",
            "password": "hunter2",
            "headers": {"Authorization": "x", "Accept": "application/json"},
            "identity": {"credential": "tok_1234", "name": "Usuario A"},
            "cookies": ["a", "b"],
        },
    )

    assert event["password"] == MASK
    assert event["headers"] == {"Authorization": MASK, "Accept": "application/json"}
    assert event["identity"] == {"credential": MASK, "name": "Usuario A"}
    assert event["cookies"] == MASK


def test_rendered_log_line_is_masked(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", "json")
    structlog.get_logger("test").info(
        "login_failed", api_key="k-123456", detail="sent Bearer zzz.yyy"
    )

    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["api_key"] == MASK
    assert "zzz.yyy" not in line["detail"]
    assert line["level"] == "info"
