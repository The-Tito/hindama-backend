"""Authentication, OWASP API2:2023 (RF-54, RF-61). Catalog: catalogo-laboratorio.md, section 6.

Every operation whose confirmed policy is not public is protected. Two kinds of cells:

- The anonymous identity, one per operation: without credentials, then (only if that was refused)
  with empty credentials. The control is an identity the policy allows.
- Each identity whose token is a JWT, on the operations it may call: its token with another
  signature, and with `alg: none`. The control is the identity itself with its real token. An
  operation that also answers without credentials is skipped: that is the anonymous cell's failure.

A failure is a 2xx whose body has the control's shape (section 4).
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from hindama.models.enums import AuthType, Module, Policy, Severity, Verdict
from hindama.scanner import jwt
from hindama.scanner.context import Actor, RunContext, Target
from hindama.scanner.evidence import Exchange
from hindama.scanner.modules import (
    ALLOWED,
    BASELINE_FAILED,
    CREDENTIAL_EXPIRED,
    DENIED,
    ERROR,
    LOGIN_FAILED,
    METHOD_NOT_SAFE,
    SAFE_METHODS,
    Cell,
    Scan,
    allowed_path,
    judge_against,
)
from hindama.scanner.recorder import CellOutcome, Detection
from hindama.scanner.requester import LoginFailedError, RequestFailedError

NO_AUTH_REQUIRED = "no_auth_required"
NOT_JWT = "not_jwt"
EMPTY_CREDENTIALS = {"Authorization": "Bearer"}  # the scheme without a value

Outcome = Callable[..., CellOutcome]  # builds the cell's outcome: observed, verdict, detections


@dataclass(frozen=True, slots=True)
class Variant:
    finding_type: str
    severity: Severity
    cwe: str
    title: str
    what: str  # how the request was sent, for the explanation


NO_CREDENTIALS = Variant(
    "authentication.no_credentials",
    Severity.HIGH,
    "CWE-306",
    "Operación protegida accesible sin credenciales",
    "sin credenciales",
)
EMPTY = Variant(
    "authentication.empty_credentials",
    Severity.HIGH,
    "CWE-287",
    "Operación protegida accesible con credenciales vacías",
    "con la cabecera Authorization vacía",
)
TAMPERED = Variant(
    "authentication.tampered_signature",
    Severity.CRITICAL,
    "CWE-347",
    "La API acepta un JWT con la firma alterada",
    "con el JWT de la identidad y otra firma",
)
ALG_NONE = Variant(
    "authentication.alg_none",
    Severity.CRITICAL,
    "CWE-347",
    "La API acepta un JWT sin firma («alg: none»)",
    "con el JWT de la identidad sin firma y «alg: none»",
)
RECOMMENDATIONS = {
    NO_CREDENTIALS.finding_type: (
        "Exige autenticación en el servidor para toda operación que no sea pública, con un "
        "control común (middleware o dependencia) que niegue por defecto."
    ),
    EMPTY.finding_type: (
        "Trata una credencial vacía o mal formada igual que una ausente: responde 401 y no "
        "continúes con un usuario por defecto."
    ),
    TAMPERED.finding_type: (
        "Verifica la firma de cada JWT con la llave del emisor antes de usar sus datos, con una "
        "biblioteca mantenida; nunca decodifiques el token sin verificarlo."
    ),
    ALG_NONE.finding_type: (
        "Fija en el servidor los algoritmos aceptados (por ejemplo, solo RS256 o HS256) y "
        "rechaza «none»; no tomes el algoritmo de la cabecera del propio token."
    ),
}


class Authentication:
    module = Module.AUTHENTICATION

    def __init__(self) -> None:
        # The anonymous answer of a path serves its cell and every JWT cell of that path.
        self._anonymous: dict[tuple[str, str], Exchange | None] = {}
        self._anonymous_locks: dict[tuple[str, str], asyncio.Lock] = {}

    def plan(self, context: RunContext) -> list[Cell]:
        protected = [t for t in context.targets if t.policy not in (None, Policy.PUBLIC)]
        anonymous = [a for a in context.actors if a.auth_type == AuthType.NONE]
        cells = [Cell(target, actor) for target in protected for actor in anonymous]
        for actor in context.actors:
            if not _may_carry_jwt(actor):
                continue
            cells += [
                Cell(target, actor)
                for target in protected
                if allowed_path(target, actor, context) is not None
            ]
        return cells

    async def evaluate(self, cell: Cell, scan: Scan) -> CellOutcome:
        target, actor = cell.target, cell.actor
        if target is None:  # plan() keeps only operations
            raise ValueError("authentication needs an operation")

        def outcome(observed: str, verdict: Verdict, *detections: Detection) -> CellOutcome:
            return CellOutcome(
                self.module, target.id, actor.id, DENIED, observed, verdict, detections
            )

        if target.method not in SAFE_METHODS:
            return outcome(METHOD_NOT_SAFE, Verdict.SKIPPED)
        if actor.auth_type == AuthType.NONE:
            return await self._without_credentials(scan, target, actor, outcome)
        return await self._forged(scan, target, actor, outcome)

    async def _without_credentials(
        self, scan: Scan, target: Target, actor: Actor, outcome: Outcome
    ) -> CellOutcome:
        found = await self._control(scan, target)
        if found is None:
            return outcome(BASELINE_FAILED, Verdict.SKIPPED)
        path, control, _ = found
        try:
            bare = await self._bare(scan, target.method, path)
            if bare is None:
                return outcome(ERROR, Verdict.ERROR)
            word = judge_against(bare, control)
            observed = f"{bare.status_code} {word}"
            if word == ALLOWED:
                return outcome(
                    observed, Verdict.FAIL, _detection(scan, target, actor, NO_CREDENTIALS, bare)
                )
            empty = await scan.requester.send_with(EMPTY_CREDENTIALS, target.method, path)
        except RequestFailedError:
            return outcome(ERROR, Verdict.ERROR)
        if judge_against(empty, control) == ALLOWED:
            observed = f"{empty.status_code} {ALLOWED}"
            return outcome(observed, Verdict.FAIL, _detection(scan, target, actor, EMPTY, empty))
        return outcome(observed, Verdict.PASS)

    async def _forged(
        self, scan: Scan, target: Target, actor: Actor, outcome: Outcome
    ) -> CellOutcome:
        if actor.expired:
            return outcome(CREDENTIAL_EXPIRED, Verdict.SKIPPED)
        path = allowed_path(target, actor, scan.context)
        if path is None:  # plan() keeps only allowed paths; an identity may expire meanwhile
            return outcome(CREDENTIAL_EXPIRED, Verdict.SKIPPED)
        try:
            token = await scan.requester.token(actor)
        except LoginFailedError:
            return outcome(LOGIN_FAILED, Verdict.SKIPPED)
        if token is None or not jwt.is_jwt(token):
            return outcome(NOT_JWT, Verdict.SKIPPED)
        control = await scan.control(actor, target.method, path)
        if control is None:
            return outcome(BASELINE_FAILED, Verdict.SKIPPED)
        try:
            bare = await self._bare(scan, target.method, path)
            if bare is not None and judge_against(bare, control) == ALLOWED:
                return outcome(NO_AUTH_REQUIRED, Verdict.SKIPPED)
            observed: list[str] = []
            detections: list[Detection] = []
            for variant, forged in (
                (TAMPERED, jwt.tampered_signature(token)),
                (ALG_NONE, jwt.alg_none(token)),
            ):
                headers = {"Authorization": f"Bearer {forged}"}
                scan.requester.masker.add(forged)
                exchange = await scan.requester.send_with(headers, target.method, path)
                word = judge_against(exchange, control)
                observed.append(f"{exchange.status_code} {word}")
                if word == ALLOWED:
                    detections.append(_detection(scan, target, actor, variant, exchange))
        except RequestFailedError:
            return outcome(ERROR, Verdict.ERROR)
        if detections:
            first = next(o for o in observed if o.endswith(ALLOWED))
            return outcome(first, Verdict.FAIL, *detections)
        return outcome(observed[0], Verdict.PASS)

    async def _control(self, scan: Scan, target: Target) -> tuple[str, Exchange, Actor] | None:
        """The first identity the policy allows, with its own path, that gets a 2xx."""
        for candidate in scan.context.actors:
            path = allowed_path(target, candidate, scan.context)
            if path is None:
                continue
            control = await scan.control(candidate, target.method, path)
            if control is not None:
                return path, control, candidate
        return None

    async def _bare(self, scan: Scan, method: str, path: str) -> Exchange | None:
        """The request without any credential, once per path; None if it got no answer."""
        key = (method, path)
        async with self._anonymous_locks.setdefault(key, asyncio.Lock()):
            if key not in self._anonymous:
                try:
                    self._anonymous[key] = await scan.requester.send_with({}, method, path)
                except RequestFailedError:
                    self._anonymous[key] = None
            return self._anonymous[key]


def _may_carry_jwt(actor: Actor) -> bool:
    """Known before any request: a bearer token that is a JWT, or a login (its token is seen
    only once it logs in; `not_jwt` if it is not one)."""
    if actor.auth_type == AuthType.LOGIN:
        return True
    token = actor.credential.token if actor.credential is not None else None
    return actor.auth_type == AuthType.BEARER and token is not None and jwt.is_jwt(token)


def _detection(
    scan: Scan, target: Target, actor: Actor, variant: Variant, exchange: Exchange
) -> Detection:
    who = "la identidad anónima" if actor.auth_type == AuthType.NONE else f"«{actor.name}»"
    return Detection(
        finding_type=variant.finding_type,
        severity=variant.severity,
        owasp_category="API2:2023",
        cwe=variant.cwe,
        title=variant.title,
        recommendation=RECOMMENDATIONS[variant.finding_type],
        explanation=(
            f"{target.method} {target.path} respondió {exchange.status_code} con datos de la misma "
            f"forma que una identidad autorizada al enviarla {variant.what} ({who}), aunque la "
            f"política confirmada exige autenticación."
        ),
        evidence=scan.requester.masker.evidence(exchange),
    )
