"""Pieces of the contract import that need no database (CU-08)."""

import pytest

from hindama.services.contracts import _clean_file_name


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (None, None),
        ("", None),
        (" \x07\x00 ", None),
        ("mi\x07contrato\n.json", "micontrato.json"),
        ("a" * 300, "a" * 255),
    ],
)
def test_the_file_name_is_printable_and_bounded(name: str | None, expected: str | None) -> None:
    assert _clean_file_name(name) == expected
