"""The test modules (F-09). Each one plans its cells, then evaluates them one by one.

A cell is `(module, operation, identity)`: one square of the access matrix (RF-64). Planning first
gives the progress its total (RF-51); a module that is not implemented yet plans no cells.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hindama.models import Identity
from hindama.models.enums import IdentityStatus, Module
from hindama.scanner.context import Actor, RunContext, Target
from hindama.scanner.recorder import CellOutcome, Recorder
from hindama.scanner.requester import Requester

PATH_PARAMETER = re.compile(r"\{([^{}/]+)\}")


@dataclass(frozen=True, slots=True)
class Cell:
    target: Target | None  # None for checks of the whole API
    actor: Actor


@dataclass(slots=True)
class Scan:
    """What a module needs to evaluate a cell."""

    context: RunContext
    requester: Requester
    recorder: Recorder
    sessions: async_sessionmaker[AsyncSession]

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
