"""The test modules (F-09). Each one plans its cells, then evaluates them one by one.

A cell is `(module, operation, identity)`: one square of the access matrix (RF-64). Planning first
gives the progress its total (RF-51); a module that is not implemented yet plans no cells.

What the modules share lives here: the vocabulary of `results`, the control request of an identity
the policy allows, and how a path is filled.
"""

import asyncio
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import quote

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hindama.models import Identity
from hindama.models.enums import (
    AuthType,
    HttpMethod,
    IdentityStatus,
    Module,
)
from hindama.scanner.context import Actor, RunContext, Target
from hindama.scanner.evidence import Exchange
from hindama.scanner.recorder import CellOutcome, Recorder
from hindama.scanner.requester import LoginFailedError, Requester, RequestFailedError

PATH_PARAMETER = re.compile(r"\{([^{}/]+)\}")
SAFE_METHODS = frozenset({HttpMethod.GET, HttpMethod.HEAD})  # RN-06: nothing else, for now

# The vocabulary of `results.expected` and `results.observed` (catalog, sections 3.1 and 4).
ALLOWED = "allowed"
DENIED = "denied"
NO_DATA = "no_data"
BASELINE_FAILED = "baseline_failed"
METHOD_NOT_SAFE = "method_not_safe"
NO_RESOURCES = "no_resources"
LOGIN_FAILED = "login_failed"
CREDENTIAL_EXPIRED = "credential_expired"
ERROR = "error"


@dataclass(frozen=True, slots=True)
class Cell:
    target: Target | None  # None for checks of the whole API
    actor: Actor


@dataclass(slots=True)
class Scan:
    """What a module needs to evaluate a cell, shared by every module of the run."""

    context: RunContext
    requester: Requester
    recorder: Recorder
    sessions: async_sessionmaker[AsyncSession]
    # A control answer is the same for every cell and module: asked once per run.
    _controls: dict[tuple[str, str, str], Exchange | None] = field(default_factory=dict)
    _control_locks: dict[tuple[str, str, str], asyncio.Lock] = field(default_factory=dict)

    async def control(self, actor: Actor, method: str, path: str) -> Exchange | None:
        """The request of an identity the policy allows: a 2xx, or None when it proves nothing."""
        key = (str(actor.id), method, path)
        async with self._control_locks.setdefault(key, asyncio.Lock()):
            if key in self._controls:
                return self._controls[key]
            result: Exchange | None = None
            if not actor.expired:
                try:
                    exchange: Exchange | None = await self.requester.send(actor, method, path)
                except (LoginFailedError, RequestFailedError):
                    exchange = None
                if exchange is not None and 200 <= exchange.status_code < 300:
                    result = exchange
                elif (
                    exchange is not None
                    and exchange.status_code == 401
                    # The login identities already logged in again; any other one expired.
                    and actor.auth_type not in (AuthType.LOGIN, AuthType.NONE)
                ):
                    await self.expire(actor)
            self._controls[key] = result
            return result

    async def expire(self, actor: Actor) -> None:
        """RF-33: the API rejected a credential that worked; its remaining cells are skipped."""
        if actor.expired:
            return
        actor.expired = True
        async with self.sessions() as session, session.begin():
            await session.execute(
                update(Identity)
                .where(Identity.id == actor.id)
                .values(status=IdentityStatus.EXPIRED_CREDENTIAL)
            )


class ScanModule(Protocol):
    module: Module

    def plan(self, context: RunContext) -> list[Cell]: ...

    async def evaluate(self, cell: Cell, scan: Scan) -> CellOutcome: ...


def path_parameters(path: str) -> list[str]:
    return PATH_PARAMETER.findall(path)


def fill(path: str, values: Mapping[str, str]) -> str:
    """The path with each parameter replaced by its value, encoded as one segment."""
    return PATH_PARAMETER.sub(lambda match: quote(values[match.group(1)], safe=""), path)
