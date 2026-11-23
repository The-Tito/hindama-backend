"""SQL injection, CWE-89 (RF-60). Catalog: catalogo-laboratorio.md, section 9.

Read only (RF-48, RN-06): GET operations, and payloads that are conditions of a read query. No
stacked queries, no writes, no time delays. One cell per GET operation with path or query
parameters, as the first authenticated identity; up to 3 parameters per operation and, for each,
at most 5 requests:

1. the base value; 2. the base value and a quote, looking for a database error the base answer did
not have (error based); 3. a true and a false condition that answer differently, the true one
answering the same when repeated, so an answer that changes by itself proves nothing (boolean
based).
"""

import re
from dataclasses import dataclass
from urllib.parse import urlencode

from hindama.models.enums import AuthType, HttpMethod, Module, Severity, Verdict
from hindama.scanner.context import Actor, Parameter, RunContext, Target
from hindama.scanner.evidence import Exchange
from hindama.scanner.modules import Cell, Scan, fill
from hindama.scanner.recorder import CellOutcome, Detection
from hindama.scanner.requester import LoginFailedError, RequestFailedError

NOT_INJECTABLE = "not_injectable"
ERROR = "error"
LOGIN_FAILED = "login_failed"
MAX_PARAMETERS = 3
NUMERIC = frozenset({"integer", "number"})
INJECTABLE_LOCATIONS = ("path", "query")

# Database errors (CWE-89): they only appear when the quote reached the query.
SQL_ERRORS = re.compile(
    "|".join(
        (
            r"SQLSTATE\[",
            r"\bORA-\d{5}\b",
            r"You have an error in your SQL syntax",
            r"\bsqlite3?\.\w*Error\b",
            r"\bSQLite3::",
            r"unrecognized token:",
            r'near "[^"]*": syntax error',
            r"syntax error at or near",
            r"unterminated quoted string",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"\bPG::\w+Error\b|\bpsycopg2?\.\w+",
            r"Microsoft OLE DB Provider for SQL Server",
            r"\bSQLException\b",
        )
    ),
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Check:
    code: str
    severity: Severity
    title: str


ERROR_BASED = Check(
    "error_based", Severity.HIGH, "Una comilla provoca un error de la base de datos"
)
BOOLEAN_BASED = Check(
    "boolean_based", Severity.CRITICAL, "Una condición SQL cambia la respuesta de la API"
)
RECOMMENDATION = (
    "Usa consultas parametrizadas (o el ORM sin SQL armado a mano) en todas las consultas: nunca "
    "concatenes valores del cliente en el texto SQL. Valida además el tipo de cada parámetro y no "
    "devuelvas los errores de la base al cliente."
)


@dataclass(frozen=True, slots=True)
class Found:
    check: Check
    parameter: Parameter
    exchange: Exchange
    payload: str


class SqlInjection:
    module = Module.SQL_INJECTION

    def plan(self, context: RunContext) -> list[Cell]:
        actor = _identity(context)
        if actor is None:
            return []
        return [Cell(t, actor) for t in context.targets if _injectable(t)]

    async def evaluate(self, cell: Cell, scan: Scan) -> CellOutcome:
        target, actor = cell.target, cell.actor
        if target is None:  # plan() keeps only operations
            raise ValueError("SQL injection needs an operation")
        found: dict[str, Found] = {}
        answered = False
        for parameter in _injectable(target)[:MAX_PARAMETERS]:
            try:
                probed = await _probe(scan, target, actor, parameter)
            except LoginFailedError:
                return self._outcome(target, actor, LOGIN_FAILED, Verdict.SKIPPED)
            except RequestFailedError:
                continue  # this parameter proves nothing; the next one may
            answered = True
            for item in probed:
                found.setdefault(item.check.code, item)
        if not answered:
            return self._outcome(target, actor, ERROR, Verdict.ERROR)
        items = [found[c.code] for c in (ERROR_BASED, BOOLEAN_BASED) if c.code in found]
        if items:
            observed = ", ".join(i.check.code for i in items)
            detections = tuple(_detection(scan, target, i) for i in items)
            return self._outcome(target, actor, observed, Verdict.FAIL, detections)
        return self._outcome(target, actor, NOT_INJECTABLE, Verdict.PASS)

    def _outcome(
        self,
        target: Target,
        actor: Actor,
        observed: str,
        verdict: Verdict,
        detections: tuple[Detection, ...] = (),
    ) -> CellOutcome:
        return CellOutcome(
            self.module, target.id, actor.id, NOT_INJECTABLE, observed, verdict, detections
        )


def _identity(context: RunContext) -> Actor | None:
    authenticated = next((a for a in context.actors if a.authenticated and not a.expired), None)
    if authenticated is not None:
        return authenticated
    return next((a for a in context.actors if a.auth_type == AuthType.NONE), None)


def _injectable(target: Target) -> list[Parameter]:
    if target.method != HttpMethod.GET:
        return []
    return [p for p in target.parameters if p.location in INJECTABLE_LOCATIONS]


def base_values(target: Target, actor: Actor, context: RunContext) -> dict[str, str]:
    """Each path and query parameter's harmless value: the identity's own resource, if any."""
    types = dict(target.resource_parameters)
    values: dict[str, str] = {}
    for parameter in target.parameters:
        if parameter.location not in INJECTABLE_LOCATIONS:
            continue
        mine = next(
            (
                owned.value
                for owned in context.resources.get(types.get(parameter.name, ""), [])
                if owned.owner_id == actor.id
            ),
            None,
        )
        values[parameter.name] = mine or ("1" if parameter.type in NUMERIC else "hindama")
    return values


def request_path(target: Target, values: dict[str, str]) -> str:
    path = fill(
        target.path, {p.name: values[p.name] for p in target.parameters if p.location == "path"}
    )
    query = [(p.name, values[p.name]) for p in target.parameters if p.location == "query"]
    return f"{path}?{urlencode(query)}" if query else path


def payloads(parameter: Parameter, base: str) -> tuple[str, str, str]:
    """(quote, true condition, false condition) for this parameter.

    `LIKE '1'` keeps its meaning when the query appends something to the value: in
    `name LIKE '%value%'` the closing `%'` turns `'1' LIKE '1` into `'1' LIKE '1%'`, still true.
    """
    if parameter.type in NUMERIC:
        return base + "'", base + " OR 1=1", base + " AND 1=2"
    return base + "'", base + "' OR '1' LIKE '1", base + "' AND '1' LIKE '2"


async def _probe(scan: Scan, target: Target, actor: Actor, parameter: Parameter) -> list[Found]:
    values = base_values(target, actor, scan.context)
    base = values[parameter.name]
    quote, true, false = payloads(parameter, base)

    async def send(value: str) -> Exchange:
        path = request_path(target, {**values, parameter.name: value})
        if actor.auth_type == AuthType.NONE:
            return await scan.requester.send_with({}, HttpMethod.GET, path)
        return await scan.requester.send(actor, HttpMethod.GET, path)

    found: list[Found] = []
    baseline = await send(base)
    quoted = await send(quote)
    if SQL_ERRORS.search(_text(quoted)) and not SQL_ERRORS.search(_text(baseline)):
        found.append(Found(ERROR_BASED, parameter, quoted, quote))
    when_true = await send(true)
    when_false = await send(false)
    if not _same(when_true, when_false):
        again = await send(true)
        if _same(when_true, again):
            found.append(Found(BOOLEAN_BASED, parameter, when_true, true))
    return found


def _same(one: Exchange, other: Exchange) -> bool:
    return one.status_code == other.status_code and one.body == other.body


def _text(exchange: Exchange) -> str:
    return exchange.body.decode("utf-8", errors="replace")


def _detection(scan: Scan, target: Target, found: Found) -> Detection:
    where = "la ruta" if found.parameter.location == "path" else "la consulta"
    if found.check is ERROR_BASED:
        explanation = (
            f"Con una comilla en el parámetro «{found.parameter.name}» ({where}) de "
            f"{target.method} {target.path}, la API respondió {found.exchange.status_code} con un "
            "error de la base de datos: el valor llega al texto de la consulta SQL."
        )
    else:
        explanation = (
            f"En el parámetro «{found.parameter.name}» ({where}) de {target.method} "
            f"{target.path}, una condición verdadera y una falsa de SQL obtuvieron respuestas "
            "distintas, y la verdadera se repitió igual: la API evalúa el valor como parte de la "
            "consulta."
        )
    return Detection(
        finding_type=f"sql_injection.{found.check.code}",
        severity=found.check.severity,
        owasp_category="API8:2023",
        cwe="CWE-89",
        title=found.check.title,
        recommendation=RECOMMENDATION,
        explanation=explanation,
        evidence=scan.requester.masker.evidence(
            found.exchange, parameter=found.parameter.name, payload=found.payload
        ),
    )
