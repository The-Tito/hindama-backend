"""Base URL validation (RF-11, ADR-008): format, scheme and destination."""

import ipaddress

import pytest

from hindama.core.destinations import (
    InvalidUrlError,
    SystemResolver,
    UnresolvedHostError,
    UrlProblem,
    check_base_url,
    is_blocked,
    parse_base_url,
)
from tests.dns import FakeResolver


@pytest.mark.parametrize(
    ("raw", "url", "host"),
    [
        ("https://api.ejemplo.com/v1", "https://api.ejemplo.com/v1", "api.ejemplo.com"),
        (
            "HTTPS://API.Ejemplo.COM:8443/v1?x=1",
            "https://api.ejemplo.com:8443/v1?x=1",
            "api.ejemplo.com",
        ),
        ("  http://ejemplo.mx  ", "http://ejemplo.mx", "ejemplo.mx"),
        ("https://ejemplo.com./", "https://ejemplo.com/", "ejemplo.com"),
        ("https://café.ejemplo.com", "https://xn--caf-dma.ejemplo.com", "xn--caf-dma.ejemplo.com"),
        ("https://93.184.215.14/api", "https://93.184.215.14/api", "93.184.215.14"),
        (
            "https://[2606:2800:21f:cb07::1]:443/",
            "https://[2606:2800:21f:cb07::1]:443/",
            "2606:2800:21f:cb07::1",
        ),
    ],
)
def test_valid_urls_are_normalized(raw: str, url: str, host: str) -> None:
    parsed = parse_base_url(raw)

    assert (parsed.url, parsed.host) == (url, host)


@pytest.mark.parametrize(
    ("raw", "problem"),
    [
        ("api.ejemplo.com", UrlProblem.INVALID_FORMAT),  # no scheme
        ("https://", UrlProblem.INVALID_FORMAT),
        ("https://usuario:clave@api.ejemplo.com", UrlProblem.INVALID_FORMAT),
        ("https://token@api.ejemplo.com", UrlProblem.INVALID_FORMAT),
        ("https://api.ejemplo.com/#inicio", UrlProblem.INVALID_FORMAT),
        ("https://api.ejemplo.com:99999", UrlProblem.INVALID_FORMAT),
        ("https://api.ejemplo.com:puerto", UrlProblem.INVALID_FORMAT),
        ("https://api ejemplo.com", UrlProblem.INVALID_FORMAT),
        ("https://api.ejemplo.com\\@otro.com", UrlProblem.INVALID_FORMAT),
        ("https://-api.ejemplo.com", UrlProblem.INVALID_FORMAT),
        ("https://api_x.ejemplo.com", UrlProblem.INVALID_FORMAT),
        ("http://127.1", UrlProblem.INVALID_FORMAT),  # IPv4 shorthands
        ("http://2130706433", UrlProblem.INVALID_FORMAT),
        ("http://0x7f.0.0.1", UrlProblem.INVALID_FORMAT),
        ("ftp://api.ejemplo.com", UrlProblem.SCHEME_NOT_ALLOWED),
        ("file:///etc/passwd", UrlProblem.SCHEME_NOT_ALLOWED),
        ("javascript://ejemplo.com", UrlProblem.SCHEME_NOT_ALLOWED),
        ("gopher://ejemplo.com", UrlProblem.SCHEME_NOT_ALLOWED),
    ],
)
def test_invalid_urls(raw: str, problem: UrlProblem) -> None:
    with pytest.raises(InvalidUrlError) as raised:
        parse_base_url(raw)

    assert raised.value.problem is problem


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.1",
        "127.0.0.1",
        "0.0.0.0",  # noqa: S104 - an address under test, not a bind
        "169.254.169.254",  # EC2 metadata
        "169.254.169.253",  # Amazon DNS
        "100.64.0.1",  # CGNAT
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fd00:ec2::254",  # EC2 metadata over IPv6
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",  # IPv4-mapped
        "::ffff:169.254.169.254",
        "2002:7f00:0001::",  # 6to4 of 127.0.0.1
        "64:ff9b::a00:1",  # NAT64 of 10.0.0.1
        "192.0.2.10",  # documentation
        "198.18.0.1",  # benchmarking
    ],
)
def test_blocked_addresses(address: str) -> None:
    assert is_blocked(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["93.184.215.14", "8.8.8.8", "2606:2800:21f:cb07::1"])
def test_public_addresses_are_allowed(address: str) -> None:
    assert not is_blocked(ipaddress.ip_address(address))


def test_own_addresses_are_blocked() -> None:
    own = [ipaddress.ip_address("8.8.4.4")]

    assert is_blocked(ipaddress.ip_address("8.8.4.4"), own)
    assert is_blocked(ipaddress.ip_address("::ffff:8.8.4.4"), own)


async def test_a_host_is_rejected_if_any_address_is_blocked() -> None:
    resolver = FakeResolver()
    resolver.set("api.ejemplo.com", "93.184.215.14", "10.0.0.7")

    with pytest.raises(InvalidUrlError) as raised:
        await check_base_url("https://api.ejemplo.com", resolver)

    assert raised.value.problem is UrlProblem.DESTINATION_NOT_ALLOWED


@pytest.mark.parametrize(
    "raw", ["http://127.0.0.1:8000", "http://[::1]/", "http://169.254.169.254/"]
)
async def test_ip_literals_are_checked_without_dns(raw: str) -> None:
    resolver = FakeResolver()

    with pytest.raises(InvalidUrlError):
        await check_base_url(raw, resolver)

    assert resolver.queries == []


async def test_localhost_is_rejected_by_its_resolution() -> None:
    resolver = FakeResolver()
    resolver.set("localhost", "127.0.0.1", "::1")

    with pytest.raises(InvalidUrlError):
        await check_base_url("http://localhost:8000", resolver)


async def test_an_unresolved_host_is_accepted_with_a_flag() -> None:
    resolver = FakeResolver()
    resolver.unresolved.add("nueva.ejemplo.com")

    checked = await check_base_url("https://nueva.ejemplo.com", resolver)

    assert checked.resolved is False
    assert checked.parsed.host == "nueva.ejemplo.com"


async def test_own_addresses_by_resolution() -> None:
    resolver = FakeResolver()
    resolver.set("hindama.ejemplo.com", "8.8.4.4")

    with pytest.raises(InvalidUrlError):
        await check_base_url(
            "https://hindama.ejemplo.com", resolver, [ipaddress.ip_address("8.8.4.4")]
        )


async def test_system_resolver_resolves_localhost() -> None:
    addresses = await SystemResolver().resolve("localhost")

    assert addresses
    assert all(address.is_loopback for address in addresses)


async def test_system_resolver_reports_unresolved_hosts() -> None:
    with pytest.raises(UnresolvedHostError):
        await SystemResolver().resolve("no-existe.invalid")  # RFC 6761: never resolves
