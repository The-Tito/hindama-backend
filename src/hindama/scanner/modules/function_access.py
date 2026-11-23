"""Function access, OWASP API5:2023 (RF-57, RF-61). Catalog: catalogo-laboratorio.md, section 5.

For each operation confirmed as admin only, and each authenticated identity that is not an
administrator: the administrator calls it first (control), then the identity. A failure is a 2xx
whose body has the control's shape (section 4). The anonymous identity is left to Authentication
(API2), so one failure is not reported twice.
"""

from hindama.models.enums import IdentityRole, Module, Policy, Severity, Verdict
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
    NO_RESOURCES,
    SAFE_METHODS,
    Cell,
    Scan,
    allowed_path,
    judge_against,
)
from hindama.scanner.recorder import CellOutcome, Detection
from hindama.scanner.requester import LoginFailedError, RequestFailedError

FINDING_TYPE = "function_access.unauthorized_call"
TITLE = "Función de administrador al alcance de otra identidad"
RECOMMENDATION = (
    "Comprueba el rol del usuario autenticado en el servidor, en cada operación administrativa, "
    "antes de ejecutarla. Niega por defecto y responde 403 a quien no sea administrador; ocultar "
    "la operación en la interfaz no la protege."
)


class FunctionAccess:
    module = Module.FUNCTION_ACCESS

    def plan(self, context: RunContext) -> list[Cell]:
        return [
            Cell(target, actor)
            for target in context.targets
            if target.policy == Policy.ADMIN_ONLY
            for actor in context.actors
            if actor.authenticated and actor.role != IdentityRole.ADMIN
        ]

    async def evaluate(self, cell: Cell, scan: Scan) -> CellOutcome:
        target, actor = cell.target, cell.actor
        if target is None:  # plan() keeps only operations
            raise ValueError("function access needs an operation")

        def outcome(observed: str, verdict: Verdict, *detections: Detection) -> CellOutcome:
            return CellOutcome(
                self.module, target.id, actor.id, DENIED, observed, verdict, detections
            )

        if target.method not in SAFE_METHODS:
            return outcome(METHOD_NOT_SAFE, Verdict.SKIPPED)
        if actor.expired:
            return outcome(CREDENTIAL_EXPIRED, Verdict.SKIPPED)
        admins = [
            (admin, path)
            for admin in scan.context.actors
            if admin.role == IdentityRole.ADMIN
            and (path := allowed_path(target, admin, scan.context)) is not None
        ]
        if not admins:
            return outcome(NO_RESOURCES, Verdict.SKIPPED)
        admin, path = admins[0]
        control = await scan.control(admin, target.method, path)
        if control is None:
            return outcome(BASELINE_FAILED, Verdict.SKIPPED)
        try:
            attack = await scan.requester.send(actor, target.method, path)
        except LoginFailedError:
            return outcome(LOGIN_FAILED, Verdict.SKIPPED)
        except RequestFailedError:
            return outcome(ERROR, Verdict.ERROR)
        word = judge_against(attack, control)
        observed = f"{attack.status_code} {word}"
        if word == ALLOWED:
            return outcome(observed, Verdict.FAIL, _detection(scan, target, actor, admin, attack))
        return outcome(observed, Verdict.PASS)


def _detection(
    scan: Scan, target: Target, actor: Actor, admin: Actor, attack: Exchange
) -> Detection:
    return Detection(
        finding_type=FINDING_TYPE,
        severity=Severity.HIGH,
        owasp_category="API5:2023",
        cwe="CWE-285",
        title=TITLE,
        recommendation=RECOMMENDATION,
        explanation=(
            f"La identidad «{actor.name}», que no es administradora, ejecutó "
            f"{target.method} {target.path} con un {attack.status_code} y recibió lo mismo que "
            f"«{admin.name}», aunque la política confirmada es «solo administrador»."
        ),
        evidence=scan.requester.masker.evidence(attack, control_identity=admin.name),
    )
