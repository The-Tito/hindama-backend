"""Resource consumption, OWASP API4:2023 (RF-59). Catalog: catalogo-laboratorio.md, section 8.

One cell for the whole API (no operation), as the first authenticated identity, with two checks
that may each yield a finding. At most 43 requests:

- **Requests limit:** up to 40 GET requests in a row to one cheap operation, at the run's pace
  (RF-47). It stops at the first 429 or 503.
- **Body size limit:** growing bodies (64 KB, 1 MB, 8 MB) to an operation whose body is a JSON
  object, each one a JSON *array*: an API that honours its contract rejects it, so nothing is
  created (RN-06). It stops at the first 413 or when the API cuts the connection.

A check that cannot conclude (no fitting operation, a first request that is not 2xx, an answer
that proves nothing) yields no finding: the module never guesses.
"""

from dataclasses import dataclass

from hindama.models.enums import AuthType, HttpMethod, Module, Policy, Severity, Verdict
from hindama.scanner.context import Actor, RunContext, Target
from hindama.scanner.evidence import Exchange
from hindama.scanner.modules import Cell, Scan, path_parameters
from hindama.scanner.recorder import CellOutcome, Detection
from hindama.scanner.requester import (
    LoginFailedError,
    OversizedResponseError,
    RequestFailedError,
)
from hindama.scanner.schemas import schema_type

LIMITED = "limited"
NOT_APPLICABLE = "not_applicable"
BURST = 40
LIMIT_STATUSES = frozenset({429, 503})
BODY_SIZES = (64 * 1024, 1024 * 1024, 8 * 1024 * 1024)
BODY_METHODS = (HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH)
READ_WHOLE = frozenset({400, 422})  # with 2xx: the API read the whole body


@dataclass(frozen=True, slots=True)
class Check:
    code: str
    severity: Severity
    cwe: str
    title: str
    recommendation: str


NO_RATE_LIMIT = Check(
    "no_rate_limit",
    Severity.MEDIUM,
    "CWE-770",
    "No se observó un límite de peticiones",
    "Limita las peticiones por cliente y por credencial (por ejemplo, con un contador por minuto "
    "en el balanceador o en la aplicación) y responde 429 con `Retry-After` al superarlo.",
)
NO_BODY_LIMIT = Check(
    "no_body_limit",
    Severity.MEDIUM,
    "CWE-400",
    "La API lee cuerpos de cualquier tamaño",
    "Fija un tamaño máximo de cuerpo en el servidor o el proxy (por ejemplo, 1 MB) y responde 413 "
    "antes de leer el resto; valida además el tamaño de cada campo.",
)


@dataclass(frozen=True, slots=True)
class Found:
    check: Check
    exchange: Exchange
    context: dict[str, object]


class ResourceConsumption:
    module = Module.RESOURCE_CONSUMPTION

    def plan(self, context: RunContext) -> list[Cell]:
        actor = _identity(context)
        return [] if actor is None else [Cell(None, actor)]

    async def evaluate(self, cell: Cell, scan: Scan) -> CellOutcome:
        found: list[Found] = []
        concluded = False
        for check in (_burst, _body):
            result = await check(scan, cell.actor)
            if result is not None:
                concluded = True
                if isinstance(result, Found):
                    found.append(result)
        detections = tuple(_detection(scan, item) for item in found)
        if found:
            observed, verdict = ", ".join(i.check.code for i in found), Verdict.FAIL
        elif concluded:
            observed, verdict = LIMITED, Verdict.PASS
        else:
            observed, verdict = NOT_APPLICABLE, Verdict.SKIPPED
        return CellOutcome(self.module, None, cell.actor.id, LIMITED, observed, verdict, detections)


def _identity(context: RunContext) -> Actor | None:
    """The first live authenticated identity, to get past authentication; else the anonymous."""
    authenticated = next((a for a in context.actors if a.authenticated and not a.expired), None)
    if authenticated is not None:
        return authenticated
    return next((a for a in context.actors if a.auth_type == AuthType.NONE), None)


def burst_target(context: RunContext) -> Target | None:
    candidates = [
        t for t in context.targets if t.method == HttpMethod.GET and not path_parameters(t.path)
    ]
    cheap = [t for t in candidates if t.policy in (Policy.PUBLIC, Policy.AUTHENTICATED)]
    return next(iter(cheap or candidates), None)


def body_target(context: RunContext) -> Target | None:
    """The first operation with a JSON object body, other than the identities' logins."""
    logins = {a.login.url for a in context.actors if a.login is not None}
    return next(
        (
            t
            for t in context.targets
            if t.method in BODY_METHODS
            and not path_parameters(t.path)
            and context.base_url + t.path not in logins
            and schema_type(context.document, t.request_schema) == "object"
        ),
        None,
    )


async def _send(
    scan: Scan, actor: Actor, method: str, path: str, content: bytes | None = None
) -> Exchange:
    headers = {"Content-Type": "application/json"} if content is not None else None
    if actor.auth_type == AuthType.NONE:
        return await scan.requester.send_with(headers or {}, method, path, content=content)
    return await scan.requester.send(actor, method, path, content=content, headers=headers)


async def _burst(scan: Scan, actor: Actor) -> Found | bool | None:
    """None: not applicable or inconclusive; True: limited; Found: no limit seen."""
    target = burst_target(scan.context)
    if target is None:
        return None
    last: Exchange | None = None
    for sent in range(1, BURST + 1):
        try:
            last = await _send(scan, actor, HttpMethod.GET, target.path)
        except (RequestFailedError, LoginFailedError):
            return None
        if last.status_code in LIMIT_STATUSES:
            return True
        if sent == 1 and not 200 <= last.status_code < 300:
            return None  # the operation wants something else: the burst proves nothing
    if last is None:  # BURST is never 0
        return None
    return Found(NO_RATE_LIMIT, last, {"requests": BURST, "operation": f"GET {target.path}"})


async def _body(scan: Scan, actor: Actor) -> Found | bool | None:
    target = body_target(scan.context)
    if target is None:
        return None
    last: Exchange | None = None
    for size in BODY_SIZES:
        try:
            last = await _send(scan, actor, target.method, target.path, _array_of(size))
        except OversizedResponseError as error:
            last = error.exchange  # an answer bigger than 1 MB: it echoed what it read
        except RequestFailedError:
            return True  # the API cut the connection: a limit
        except LoginFailedError:
            return None
        if last.status_code == 413:
            return True
    if last is None:  # BODY_SIZES is never empty
        return None
    if 200 <= last.status_code < 300 or last.status_code in READ_WHOLE:
        return Found(
            NO_BODY_LIMIT,
            last,
            {"request_body_bytes": BODY_SIZES[-1], "operation": f"{target.method} {target.path}"},
        )
    return None  # 401, 5xx...: it does not prove the body was read


def _array_of(size: int) -> bytes:
    """A JSON array of exactly `size` bytes: `["aaa…"]`."""
    return b'["' + b"a" * (size - 4) + b'"]'


def _detection(scan: Scan, found: Found) -> Detection:
    exchange = found.exchange
    if found.check is NO_RATE_LIMIT:
        explanation = (
            f"Se enviaron {BURST} peticiones seguidas a {found.context['operation']} y ninguna "
            f"recibió 429 ni 503: no se observó un límite de peticiones (la última respondió "
            f"{exchange.status_code})."
        )
    else:
        explanation = (
            f"{found.context['operation']} recibió un cuerpo de "
            f"{BODY_SIZES[-1] // (1024 * 1024)} MB y respondió {exchange.status_code}, sin 413: "
            "la API lo leyó completo."
        )
    return Detection(
        finding_type=f"resource_consumption.{found.check.code}",
        severity=found.check.severity,
        owasp_category="API4:2023",
        cwe=found.check.cwe,
        title=found.check.title,
        recommendation=found.check.recommendation,
        explanation=explanation,
        evidence=scan.requester.masker.evidence(exchange, **found.context),
    )
