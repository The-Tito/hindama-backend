"""Test doubles for ownership verification: tests never query real DNS or reach real hosts."""

from hindama.core.ownership import CheckResult, Outcome, TxtLookupError
from hindama.models.enums import VerificationMethod


class FakeTxtResolver:
    """TXT records by name; a name in `failing` behaves like a DNS that does not answer."""

    def __init__(self) -> None:
        self.records: dict[str, list[str]] = {}
        self.failing: set[str] = set()
        self.queries: list[str] = []

    async def txt(self, name: str) -> list[str]:
        self.queries.append(name)
        if name in self.failing:
            raise TxtLookupError(name)
        return self.records.get(name, [])


class ScriptedChecker:
    """Answers with a fixed result per method, without any network. By default the file method
    cannot connect and the DNS method verifies."""

    def __init__(self) -> None:
        self.results = {
            VerificationMethod.FILE: CheckResult(Outcome.CONNECTION_ERROR),
            VerificationMethod.DNS: CheckResult(Outcome.VERIFIED),
        }
        self.calls: list[tuple[VerificationMethod, str, str, str]] = []

    async def check(
        self, method: VerificationMethod, *, base_url: str, host: str, code: str
    ) -> CheckResult:
        self.calls.append((method, base_url, host, code))
        return self.results[method]
