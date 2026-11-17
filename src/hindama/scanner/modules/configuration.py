"""Configuration, OWASP API8:2023 (RF-55). Catalog: catalogo-laboratorio.md, section 7.

One cell for the whole API (no operation, the anonymous identity) that may yield several
findings, each with its own fingerprint. At most 6 GET requests:

1. The main one, anonymous, with an untrusted `Origin`: security headers, CORS and versions.
2. A route that does not exist, and up to 3 GET operations with a malformed path value: error
   details. These go as the first authenticated identity, to get past authentication to the code
   that fails. The value carries no quotes nor SQL: that is the SQL injection module's job.
"""

import re
from dataclasses import dataclass

from hindama.models.enums import AuthType, HttpMethod, Module, Severity, Verdict
from hindama.scanner.context import Actor, RunContext
from hindama.scanner.evidence import Exchange
from hindama.scanner.modules import Cell, Scan, fill, path_parameters
from hindama.scanner.recorder import CellOutcome, Detection
from hindama.scanner.requester import LoginFailedError, RequestFailedError

HARDENED = "hardened"
ERROR = "error"
UNTRUSTED_ORIGIN = "https://origen-no-confiable.hindama.invalid"
MISSING_ROUTE = "/hindama-ruta-inexistente"
MALFORMED = "hindama" + "z" * 57  # a long string where an identifier is expected
MAX_MALFORMED = 3

# Error details (CWE-209): stack traces, database errors and server paths, only in 4xx/5xx.
INTERNAL_DETAILS = re.compile(
    "|".join(
        (
            r"Traceback \(most recent call last\)",
            r'File "[^"]+", line \d+',
            r"\bat [\w$.]+\([\w$]+\.java:\d+\)",
            r"Exception in thread \"",
            r"Server Error in '/' Application",
            r"\bat .+ \(.+\.js:\d+:\d+\)",
            r"node_modules/",
            r"Fatal error: .+ on line \d+",
            r"Stack trace:",
            r"SQLSTATE\[",
            r"\bORA-\d{5}\b",
            r"You have an error in your SQL syntax",
            r"\bPG::\w+Error\b|\bpsycopg2?\.\w+",
            r"Unclosed quotation mark",
            r"\bsqlite3?\.\w*Error\b",
            r"(?:/usr/(?:src|lib|local)/|/var/www/|/home/[\w.-]+/|/app/[\w/.-]+\.py)",
            r"[A-Z]:\\\\(?:Users|inetpub|Program Files)",
        )
    )
)
VERSION = re.compile(r"\d+\.\d+")


@dataclass(frozen=True, slots=True)
class Check:
    code: str  # the end of `finding_type`, also shown in `observed`
    severity: Severity
    cwe: str
    title: str
    recommendation: str


HSTS = Check(
    "missing_header.hsts",
    Severity.LOW,
    "CWE-319",
    "Falta la cabecera Strict-Transport-Security",
    "Envía `Strict-Transport-Security: max-age=31536000; includeSubDomains` en todas las "
    "respuestas HTTPS, para que el navegador nunca vuelva a usar HTTP.",
)
NOSNIFF = Check(
    "missing_header.nosniff",
    Severity.LOW,
    "CWE-693",
    "Falta la cabecera X-Content-Type-Options",
    "Envía `X-Content-Type-Options: nosniff` para que el navegador respete el tipo declarado de "
    "cada respuesta.",
)
FRAMES = Check(
    "missing_header.frame_options",
    Severity.LOW,
    "CWE-1021",
    "Las respuestas se pueden incrustar en marcos de otros sitios",
    "Envía `X-Frame-Options: DENY` o `Content-Security-Policy: frame-ancestors 'none'`.",
)
CORS = Check(
    "cors.any_origin_with_credentials",
    Severity.MEDIUM,
    "CWE-942",
    "CORS acepta cualquier origen con credenciales",
    "Responde `Access-Control-Allow-Origin` solo para una lista fija de orígenes propios; nunca "
    "copies el `Origin` recibido ni uses `*` junto con `Access-Control-Allow-Credentials: true`.",
)
ERROR_DETAILS = Check(
    "error_details",
    Severity.MEDIUM,
    "CWE-209",
    "Los errores exponen detalles internos",
    "Devuelve al cliente un mensaje genérico y un identificador de la petición; deja la traza, "
    "las consultas y las rutas solo en los registros del servidor.",
)
VERSION_DISCLOSURE = Check(
    "version_disclosure",
    Severity.INFO,
    "CWE-200",
    "Las cabeceras anuncian la versión del software",
    "Quita la versión de `Server` y `X-Powered-By` (o la cabecera completa): facilita buscar "
    "vulnerabilidades conocidas de esa versión.",
)


class Configuration:
    module = Module.CONFIGURATION

    def plan(self, context: RunContext) -> list[Cell]:
        anonymous = next((a for a in context.actors if a.auth_type == AuthType.NONE), None)
        return [] if anonymous is None else [Cell(None, anonymous)]

    async def evaluate(self, cell: Cell, scan: Scan) -> CellOutcome:
        context, requester = scan.context, scan.requester
        found: list[tuple[Check, Exchange]] = []
        answered = False
        try:
            main: Exchange | None = await requester.send_with(
                {"Origin": UNTRUSTED_ORIGIN}, HttpMethod.GET, _main_path(context)
            )
        except RequestFailedError:
            main = None
        if main is not None:
            answered = True
            secure = context.base_url.lower().startswith("https://")
            found += [(check, main) for check in _missing_headers(main, secure=secure)]
            if _cors_accepts_anyone(main):
                found.append((CORS, main))
            if _discloses_version(main):
                found.append((VERSION_DISCLOSURE, main))
        actor = _error_identity(context)
        for path in [MISSING_ROUTE, *_malformed_paths(context)]:
            try:
                exchange = await _send_for_errors(scan, actor, path)
            except (RequestFailedError, LoginFailedError):
                continue
            answered = True
            if exchange.status_code >= 400 and INTERNAL_DETAILS.search(_text(exchange)):
                found.append((ERROR_DETAILS, exchange))
                break  # one exchange proves it
        detections = tuple(_detection(scan, check, exchange) for check, exchange in found)
        if found:
            observed = ", ".join(check.code for check, _ in found)
            verdict = Verdict.FAIL
        else:
            observed, verdict = (HARDENED, Verdict.PASS) if answered else (ERROR, Verdict.ERROR)
        return CellOutcome(
            self.module, None, cell.actor.id, HARDENED, observed, verdict, detections
        )


def _main_path(context: RunContext) -> str:
    """The first GET operation without path parameters, or the base URL itself."""
    return next(
        (
            target.path
            for target in context.targets
            if target.method == HttpMethod.GET and not path_parameters(target.path)
        ),
        "",
    )


def _malformed_paths(context: RunContext) -> list[str]:
    paths = [
        fill(target.path, dict.fromkeys(path_parameters(target.path), MALFORMED))
        for target in context.targets
        if target.method == HttpMethod.GET and path_parameters(target.path)
    ]
    return paths[:MAX_MALFORMED]


def _error_identity(context: RunContext) -> Actor | None:
    """The first authenticated identity, to get past authentication; None sends anonymously."""
    return next((a for a in context.actors if a.authenticated and not a.expired), None)


async def _send_for_errors(scan: Scan, actor: Actor | None, path: str) -> Exchange:
    if actor is None:
        return await scan.requester.send_with({}, HttpMethod.GET, path)
    return await scan.requester.send(actor, HttpMethod.GET, path)


def _missing_headers(exchange: Exchange, *, secure: bool) -> list[Check]:
    headers = {name.lower(): value for name, value in exchange.response_headers}
    missing = []
    if secure and "strict-transport-security" not in headers:
        missing.append(HSTS)
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        missing.append(NOSNIFF)
    policy = headers.get("content-security-policy", "").lower()
    if "x-frame-options" not in headers and "frame-ancestors" not in policy:
        missing.append(FRAMES)
    return missing


def _cors_accepts_anyone(exchange: Exchange) -> bool:
    headers = {name.lower(): value.strip() for name, value in exchange.response_headers}
    origin = headers.get("access-control-allow-origin")
    credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    return credentials and origin in (UNTRUSTED_ORIGIN, "*")


def _discloses_version(exchange: Exchange) -> bool:
    return any(
        name.lower() in ("server", "x-powered-by") and VERSION.search(value)
        for name, value in exchange.response_headers
    )


def _text(exchange: Exchange) -> str:
    return exchange.body.decode("utf-8", errors="replace")


def _detection(scan: Scan, check: Check, exchange: Exchange) -> Detection:
    return Detection(
        finding_type=f"configuration.{check.code}",
        severity=check.severity,
        owasp_category="API8:2023",
        cwe=check.cwe,
        title=check.title,
        recommendation=check.recommendation,
        explanation=(
            f"{check.title}: se observó en la respuesta {exchange.status_code} a "
            f"{exchange.method} {exchange.url}."
        ),
        evidence=scan.requester.masker.evidence(exchange),
    )
