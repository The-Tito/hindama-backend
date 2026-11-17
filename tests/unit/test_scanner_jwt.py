"""Forged JWTs of API2 (RF-54) and the shape rule shared by API5 and API2 (RF-61)."""

import base64
import json

import pytest

from hindama.scanner import jwt
from hindama.scanner.evidence import Exchange
from hindama.scanner.modules import ALLOWED, DENIED, NO_DATA, judge_against, same_shape
from tests.lab.app import ANA_TOKEN, read_jwt


def part(token: str, index: int) -> bytes:
    raw = token.split(".")[index]
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (ANA_TOKEN, True),
        ("tok-beto-laboratorio-7c1e", False),
        ("a.b.c", False),  # not base64 JSON
        ("e30.e30.", False),  # `{}`: a header without `alg`
        ("..", False),
    ],
)
def test_what_is_a_jwt(token: str, expected: bool) -> None:
    assert jwt.is_jwt(token) is expected


def test_a_tampered_signature_keeps_the_claims() -> None:
    forged = jwt.tampered_signature(ANA_TOKEN)

    assert forged.split(".")[:2] == ANA_TOKEN.split(".")[:2]
    assert part(forged, 2) != part(ANA_TOKEN, 2)
    assert len(part(forged, 2)) == len(part(ANA_TOKEN, 2))
    assert read_jwt(forged, verify=True) is None  # a verifying API rejects it
    assert read_jwt(forged, verify=False) == "ana"  # a broken one does not notice


def test_alg_none_drops_the_signature() -> None:
    forged = jwt.alg_none(ANA_TOKEN)

    assert json.loads(part(forged, 0)) == {"alg": "none", "typ": "JWT"}
    assert forged.split(".")[1] == ANA_TOKEN.split(".")[1]
    assert forged.endswith(".")
    assert read_jwt(forged, verify=True) is None


def test_an_unsigned_token_gets_a_signature() -> None:
    unsigned = jwt.alg_none(ANA_TOKEN)

    assert jwt.tampered_signature(unsigned).split(".")[2] != ""


def exchange(status: int, body: object) -> Exchange:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return Exchange("GET", "http://x/", {}, status, (), raw)


@pytest.mark.parametrize(
    ("attack", "control", "shaped"),
    [
        ({"a": 1, "b": 2}, {"b": 9, "a": 0}, True),  # same keys, other values
        ({"error": "forbidden"}, {"entries": []}, False),  # the decoy
        ([], [{"id": 1}], True),  # two lists
        ([], {"items": []}, False),
        (b"<html>ok</html>", b"<html>ok</html>", True),
        (b"<html>a</html>", b"<html>b</html>", False),
    ],
)
def test_the_shape_rule(attack: object, control: object, shaped: bool) -> None:
    assert same_shape(exchange(200, attack), exchange(200, control)) is shaped


def test_the_judgement_against_a_control() -> None:
    control = exchange(200, {"entries": [1]})

    assert judge_against(exchange(200, {"entries": []}), control) == ALLOWED
    assert judge_against(exchange(200, {"error": "x"}), control) == NO_DATA
    assert judge_against(exchange(204, b""), control) == NO_DATA
    assert judge_against(exchange(401, {"entries": []}), control) == DENIED
