"""Object access, OWASP API1:2023 (RF-56, RF-61). Catalog: catalogo-laboratorio.md, section 3.

For each operation whose confirmed policy requires ownership, and each authenticated identity:

1. Victims: up to `MAX_VICTIMS` resources of the operation's type owned by other identities.
2. Control: the owner asks for its resource. If even the owner gets no 2xx, the resource proves
   nothing (`baseline_failed`).
3. Attack: the identity asks for the same resource. It is a failure only with a 2xx, a non-empty
   body, and a body that carries the resource's identifier or equals the owner's. A 200 with an
   error in its body is not an access (RF-61).

Only GET and HEAD are sent: other methods wait for resources created by the platform (RN-06).
"""

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass
from uuid import UUID

from hindama.models.enums import (
    OWNERSHIP_POLICIES,
    AuthType,
    HttpMethod,
    IdentityRole,
    Module,
    Policy,
    Severity,
    Verdict,
)
from hindama.scanner.context import Actor, Owned, RunContext, Target
from hindama.scanner.evidence import Exchange
from hindama.scanner.modules import Cell, Scan, fill, path_parameters
from hindama.scanner.recorder import CellOutcome, Detection
from hindama.scanner.requester import LoginFailedError, RequestFailedError

FINDING_TYPE = "object_access.unauthorized_read"
MAX_VICTIMS = 3
SAFE_METHODS = frozenset({HttpMethod.GET, HttpMethod.HEAD})
MIN_TEXT_ID = 4  # outside JSON, a shorter identifier would match by chance

# The vocabulary of `results.expected` and `results.observed` (catalog, section 3.1).
ALLOWED = "allowed"
DENIED = "denied"
NO_DATA = "no_data"
BASELINE_FAILED = "baseline_failed"
METHOD_NOT_SAFE = "method_not_safe"
NO_RESOURCES = "no_resources"
LOGIN_FAILED = "login_failed"
CREDENTIAL_EXPIRED = "credential_expired"
ERROR = "error"

TITLE = "Acceso a un objeto de otra identidad"
RECOMMENDATION = (
    "Comprueba en el servidor, en cada petición, que el objeto solicitado pertenece al usuario "
    "autenticado antes de devolverlo, y responde 404 si no es suyo. No confíes en que el "
    "identificador sea difícil de adivinar."
)


@dataclass(frozen=True, slots=True)
class Victim:
    path: str
    owned: Owned
    owner: Actor
    resource_type: str


class ObjectAccess:
    module = Module.OBJECT_ACCESS

    def __init__(self) -> None:
        # The owner's answer is the same for every attacker: asked once per run and path.
        self._baselines: dict[str, Exchange | None] = {}
        self._baseline_locks: dict[str, asyncio.Lock] = {}

    def plan(self, context: RunContext) -> list[Cell]:
        return [
            Cell(target, actor)
            for target in context.targets
            if _testable(target)
            for actor in context.actors
            if actor.authenticated
        ]

    async def evaluate(self, cell: Cell, scan: Scan) -> CellOutcome:
        target, actor = cell.target, cell.actor
        if target is None or target.policy is None:  # plan() keeps only those
            raise ValueError("object access needs an operation with a policy")
        admin_allowed = actor.role == IdentityRole.ADMIN and target.policy == Policy.OWNER_OR_ADMIN
        expected = ALLOWED if admin_allowed else DENIED

        def outcome(
            observed: str, verdict: Verdict, detection: Detection | None = None
        ) -> CellOutcome:
            return CellOutcome(
                self.module, target.id, actor.id, expected, observed, verdict, detection
            )

        if target.method not in SAFE_METHODS:
            return outcome(METHOD_NOT_SAFE, Verdict.SKIPPED)
        if actor.expired:
            return outcome(CREDENTIAL_EXPIRED, Verdict.SKIPPED)
        victims = list(_victims(target, actor, scan.context))
        if not victims:
            return outcome(NO_RESOURCES, Verdict.SKIPPED)
        first: str | None = None
        controls = errors = 0
        for victim in victims:
            baseline = await self._baseline(scan, target, victim)
            if baseline is None:
                continue
            controls += 1
            try:
                attack = await scan.requester.send(actor, target.method, victim.path)
            except LoginFailedError:
                return outcome(LOGIN_FAILED, Verdict.SKIPPED)
            except RequestFailedError:
                errors += 1
                continue
            word = _judge(attack, baseline, victim.owned.value)
            observed = f"{attack.status_code} {word}"
            if word == ALLOWED and expected == DENIED:
                return outcome(
                    observed, Verdict.FAIL, _detection(scan, target, actor, victim, attack)
                )
            first = first or observed
        if first is not None:
            return outcome(first, Verdict.PASS)
        if controls == 0:
            return outcome(BASELINE_FAILED, Verdict.SKIPPED)
        return outcome(ERROR, Verdict.ERROR)

    async def _baseline(self, scan: Scan, target: Target, victim: Victim) -> Exchange | None:
        """The owner's own request: a 2xx, or None when it proves nothing."""
        lock = self._baseline_locks.setdefault(victim.path, asyncio.Lock())
        async with lock:
            if victim.path in self._baselines:
                return self._baselines[victim.path]
            result: Exchange | None = None
            if not victim.owner.expired:
                try:
                    exchange = await scan.requester.send(victim.owner, target.method, victim.path)
                except (LoginFailedError, RequestFailedError):
                    exchange = None
                if exchange is not None and 200 <= exchange.status_code < 300:
                    result = exchange
                elif (
                    exchange is not None
                    and exchange.status_code == 401
                    # The login identities already logged in again; any other one expired.
                    and victim.owner.auth_type != AuthType.LOGIN
                ):
                    await scan.expire(victim.owner)
            self._baselines[victim.path] = result
            return result


def _testable(target: Target) -> bool:
    """A confirmed ownership policy, and every path parameter is a resource (RF-35)."""
    if target.policy not in OWNERSHIP_POLICIES or not target.resource_parameters:
        return False
    declared = {name for name, _ in target.resource_parameters}
    return set(path_parameters(target.path)) <= declared


def _victims(target: Target, actor: Actor, context: RunContext) -> Iterator[Victim]:
    """Resources of other live identities, the last path parameter being the one attacked; the
    other parameters take the victim owner's own resources (`/users/{u}/orders/{o}`)."""
    types = dict(target.resource_parameters)
    names = path_parameters(target.path)
    if not names:
        return
    attacked = names[-1]
    found = 0
    for owned in context.resources.get(types[attacked], []):
        owner = context.actor(owned.owner_id)
        if owner is None or owner.id == actor.id or not owner.authenticated:
            continue
        values = {attacked: owned.value}
        for name in names[:-1]:
            mine = _first_of(context, types[name], owner.id)
            if mine is None:
                break
            values[name] = mine
        else:
            yield Victim(fill(target.path, values), owned, owner, types[attacked])
            found += 1
            if found == MAX_VICTIMS:
                return


def _first_of(context: RunContext, resource_type: str, owner_id: UUID) -> str | None:
    return next(
        (o.value for o in context.resources.get(resource_type, []) if o.owner_id == owner_id),
        None,
    )


def _judge(attack: Exchange, baseline: Exchange, value: str) -> str:
    if not 200 <= attack.status_code < 300:
        return DENIED
    if attack.body and (attack.body == baseline.body or _carries(attack.body, value)):
        return ALLOWED
    return NO_DATA


def _carries(body: bytes, value: str) -> bool:
    """The identifier as a whole JSON value anywhere in the body, or as text outside JSON."""
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return len(value) >= MIN_TEXT_ID and value.encode() in body
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif (
            isinstance(node, str | int | float)
            and not isinstance(node, bool)
            and str(node) == value
        ):
            return True
    return False


def _detection(
    scan: Scan, target: Target, actor: Actor, victim: Victim, attack: Exchange
) -> Detection:
    who = "solo al propietario"
    if target.policy == Policy.OWNER_OR_ADMIN:
        who = "solo al propietario o a un administrador"
    return Detection(
        finding_type=FINDING_TYPE,
        severity=Severity.HIGH,
        owasp_category="API1:2023",
        cwe="CWE-639",
        title=TITLE,
        recommendation=RECOMMENDATION,
        explanation=(
            f"La identidad «{actor.name}» obtuvo el recurso «{victim.owned.value}» "
            f"({victim.resource_type}) de «{victim.owner.name}» con un {attack.status_code}, "
            f"aunque la política confirmada de la operación permite el acceso {who}."
        ),
        evidence=scan.requester.masker.evidence(
            attack,
            resource={
                "type": victim.resource_type,
                "value": victim.owned.value,
                "owner": victim.owner.name,
            },
        ),
    )
