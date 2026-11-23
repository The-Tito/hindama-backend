"""A fake DNS: tests never depend on the network or on real records."""

import ipaddress

from hindama.core.destinations import IPAddress, UnresolvedHostError

PUBLIC_IP = ipaddress.ip_address("93.184.215.14")


class FakeResolver:
    """Every host resolves to a public address unless a test says otherwise."""

    def __init__(self) -> None:
        self.records: dict[str, list[IPAddress]] = {}
        self.unresolved: set[str] = set()
        self.queries: list[str] = []

    def set(self, host: str, *addresses: str) -> None:
        self.records[host] = [ipaddress.ip_address(a) for a in addresses]

    async def resolve(self, host: str) -> list[IPAddress]:
        self.queries.append(host)
        if host in self.unresolved:
            raise UnresolvedHostError(host)
        return self.records.get(host, [PUBLIC_IP])
