"""Validation of the destinations the platform may reach (RF-11, ADR-008).

This module only decides whether a URL and the addresses its host resolves to are allowed. It is
used when a base URL is registered and, later, by `safe_http` before every outgoing request (which
also pins the connection to the validated address; validating at registration alone is not enough
against DNS rebinding).
"""

import asyncio
import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

ALLOWED_SCHEMES = frozenset({"http", "https"})
DNS_TIMEOUT_SECONDS = 3.0

# Explicit list on top of `is_global`, so the intent is readable and tested (ADR-008, step 2).
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8",
        "169.254.0.0/16",  # link local, includes the EC2 metadata service
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, includes broadcast
        "::/128",
        "::1/128",
        "fc00::/7",  # unique local, includes fd00:ec2::254 (metadata over IPv6)
        "fe80::/10",
        "ff00::/8",
    )
)


class UrlProblem(StrEnum):
    """`errors[].code` of the base URL (convenciones.md 8.2)."""

    INVALID_FORMAT = "url.invalid_format"
    SCHEME_NOT_ALLOWED = "url.scheme_not_allowed"
    DESTINATION_NOT_ALLOWED = "url.destination_not_allowed"


class InvalidUrlError(Exception):
    def __init__(self, problem: UrlProblem) -> None:
        super().__init__(problem.value)
        self.problem = problem


class UnresolvedHostError(Exception):
    """The host has no A/AAAA records yet (or DNS did not answer in time)."""


class Resolver(Protocol):
    async def resolve(self, host: str) -> list[IPAddress]: ...


class SystemResolver:
    """A and AAAA records through the operating system, with a timeout."""

    async def resolve(self, host: str) -> list[IPAddress]:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), DNS_TIMEOUT_SECONDS
            )
        except (TimeoutError, socket.gaierror, UnicodeError) as error:
            raise UnresolvedHostError(host) from error
        addresses = {ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos}
        if not addresses:
            raise UnresolvedHostError(host)
        return sorted(addresses, key=lambda a: (a.version, int(a)))


@dataclass(frozen=True, slots=True)
class ParsedUrl:
    url: str  # normalized: lowercase scheme and host, host in IDNA (punycode)
    scheme: str
    host: str  # without port or brackets; what ownership verification checks (RF-17)
    ip_literal: IPAddress | None


def parse_base_url(raw: str) -> ParsedUrl:
    """Format and scheme checks (RF-11). Does not touch the network."""
    try:
        parts = urlsplit(raw.strip())
        port = parts.port  # raises ValueError if it is not a number in range
    except ValueError as error:
        raise InvalidUrlError(UrlProblem.INVALID_FORMAT) from error

    scheme = parts.scheme.lower()
    if not scheme:
        raise InvalidUrlError(UrlProblem.INVALID_FORMAT)
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidUrlError(UrlProblem.SCHEME_NOT_ALLOWED)
    if not parts.netloc:
        raise InvalidUrlError(UrlProblem.INVALID_FORMAT)
    # Credentials in the URL would end up in logs and evidence; fragments are never sent.
    if "@" in parts.netloc or parts.fragment or "#" in raw:
        raise InvalidUrlError(UrlProblem.INVALID_FORMAT)
    if any(char.isspace() or ord(char) < 0x20 for char in raw.strip()) or "\\" in raw:
        raise InvalidUrlError(UrlProblem.INVALID_FORMAT)

    host, ip_literal = _normalize_host(parts)
    netloc = f"[{host}]" if isinstance(ip_literal, ipaddress.IPv6Address) else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    path = parts.path or ""
    query = f"?{parts.query}" if parts.query else ""
    return ParsedUrl(
        url=f"{scheme}://{netloc}{path}{query}", scheme=scheme, host=host, ip_literal=ip_literal
    )


def _normalize_host(parts: SplitResult) -> tuple[str, IPAddress | None]:
    hostname = parts.hostname  # lowercased, without brackets
    if not hostname:
        raise InvalidUrlError(UrlProblem.INVALID_FORMAT)
    try:
        return str(ipaddress.ip_address(hostname)), ipaddress.ip_address(hostname)
    except ValueError:
        pass
    hostname = hostname.rstrip(".")
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise InvalidUrlError(UrlProblem.INVALID_FORMAT) from error
    labels = ascii_host.split(".")
    valid = (
        0 < len(ascii_host) <= 253
        and all(0 < len(label) <= 63 for label in labels)
        and all(label.replace("-", "").isalnum() for label in labels)
        and not any(label.startswith("-") or label.endswith("-") for label in labels)
    )
    if not valid:
        raise InvalidUrlError(UrlProblem.INVALID_FORMAT)
    try:  # "127.1", "2130706433" or "0x7f.0.0.1": IPv4 shorthands some resolvers accept
        socket.inet_aton(ascii_host)
    except OSError:
        return ascii_host, None
    raise InvalidUrlError(UrlProblem.INVALID_FORMAT)


def _embedded_ipv4(address: IPAddress) -> ipaddress.IPv4Address | None:
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        if address.sixtofour is not None:
            return address.sixtofour
        if address.teredo is not None:
            return address.teredo[1]
        if address in ipaddress.ip_network("64:ff9b::/96"):  # NAT64
            return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def is_blocked(address: IPAddress, own_addresses: Iterable[IPAddress] = ()) -> bool:
    """Private, loopback, link local, metadata, reserved, multicast or Hindama's own IPs."""
    embedded = _embedded_ipv4(address)
    if embedded is not None and is_blocked(embedded, own_addresses):
        return True
    if address in set(own_addresses):
        return True
    if any(address in network for network in _BLOCKED_NETWORKS):
        return True
    return not address.is_global


@dataclass(frozen=True, slots=True)
class CheckedUrl:
    parsed: ParsedUrl
    resolved: bool  # False: the host does not resolve yet (warning `url.unresolved`)


async def check_base_url(
    raw: str, resolver: Resolver, own_addresses: Iterable[IPAddress] = ()
) -> CheckedUrl:
    """RF-11: format, scheme and destination. Rejects if ANY resolved address is blocked."""
    parsed = parse_base_url(raw)
    own = tuple(own_addresses)
    if parsed.ip_literal is not None:
        if is_blocked(parsed.ip_literal, own):
            raise InvalidUrlError(UrlProblem.DESTINATION_NOT_ALLOWED)
        return CheckedUrl(parsed, resolved=True)
    try:
        addresses = await resolver.resolve(parsed.host)
    except UnresolvedHostError:
        return CheckedUrl(parsed, resolved=False)
    if any(is_blocked(address, own) for address in addresses):
        raise InvalidUrlError(UrlProblem.DESTINATION_NOT_ALLOWED)
    return CheckedUrl(parsed, resolved=True)
