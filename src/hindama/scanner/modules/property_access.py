"""Property access, OWASP API3:2023 (RF-58). Catalog: catalogo-laboratorio.md, section 10.

Two kinds of cell, as the first authenticated identity:

- **Undeclared fields** (read only): a GET whose 2xx JSON schema lists its properties. One request
  (the shared control, so usually none extra); a failure is a top-level field the schema does not
  declare.
- **Mass assignment** (writes, RN-06): a POST with a JSON object body whose created item the
  contract can delete (`POST /x` and `DELETE /x/{id}`). The resource is noted in
  `created_resources` before it is created, created with protected fields, compared, and deleted
  as the same identity, also when the run is cancelled. Without that DELETE nothing is written.
"""

import asyncio
import json
from collections.abc import Coroutine
from typing import Any
from uuid import UUID

from sqlalchemy import insert, update

from hindama.models import CreatedResource
from hindama.models.enums import CreatedResourceStatus, HttpMethod, Module, Severity, Verdict
from hindama.scanner.context import Actor, RunContext, Target
from hindama.scanner.evidence import Exchange
from hindama.scanner.limiter import BudgetExhaustedError
from hindama.scanner.modules import (
    BASELINE_FAILED,
    ERROR,
    LOGIN_FAILED,
    NO_RESOURCES,
    Cell,
    Scan,
    fill,
    own_path,
    path_parameters,
)
from hindama.scanner.recorder import CellOutcome, Detection
from hindama.scanner.requester import LoginFailedError, RequestFailedError
from hindama.scanner.schemas import deref, schema_type

DECLARED_ONLY = "declared_only"
UNDECLARED = "undeclared_fields"
REJECTED = "rejected"
ACCEPTED = "accepted"
NOT_CREATED = "not_created"
BUDGET_RESERVED = "budget_reserved"
DELETE_ATTEMPTS = 3
PRIVILEGE_NAMES = (
    "role",
    "is_admin",
    "isAdmin",
    "admin",
    "permissions",
    "owner",
    "owner_id",
    "user_id",
    "balance",
    "verified",
    "is_verified",
)
BOOLEAN_NAMES = frozenset({"is_admin", "isAdmin", "admin", "verified", "is_verified"})
ASSIGNED = "hindama-asignado"
_CLEANUPS: set[asyncio.Future[CreatedResourceStatus]] = set()  # outlives a cancelled cell

UNDECLARED_RECOMMENDATION = (
    "Devuelve solo los campos que el cliente necesita: serializa cada respuesta con un esquema de "
    "salida explícito (una lista blanca de campos) en lugar del objeto completo de la base."
)
MASS_ASSIGNMENT_RECOMMENDATION = (
    "Copia del cuerpo solo los campos que el cliente puede fijar (una lista blanca por operación) "
    "y asigna en el servidor el dueño, el rol y los demás campos protegidos; rechaza o ignora el "
    "resto."
)


class PropertyAccess:
    module = Module.PROPERTY_ACCESS

    def plan(self, context: RunContext) -> list[Cell]:
        actor = next((a for a in context.actors if a.authenticated and not a.expired), None)
        if actor is None:
            return []
        return [
            Cell(target, actor)
            for target in context.targets
            if listed_properties(context.document, target) is not None
            or delete_for(context, target) is not None
        ]

    async def evaluate(self, cell: Cell, scan: Scan) -> CellOutcome:
        target, actor = cell.target, cell.actor
        if target is None:  # plan() keeps only operations
            raise ValueError("property access needs an operation")
        if target.method == HttpMethod.GET:
            return await self._undeclared(target, actor, scan)
        delete = delete_for(scan.context, target)
        if delete is None:  # plan() keeps only these
            raise ValueError("mass assignment needs a DELETE")
        return await self._mass_assignment(target, delete, actor, scan)

    def _outcome(
        self,
        target: Target,
        actor: Actor,
        expected: str,
        observed: str,
        verdict: Verdict,
        *detections: Detection,
    ) -> CellOutcome:
        return CellOutcome(
            self.module, target.id, actor.id, expected, observed, verdict, detections
        )

    # -------------------------------------------------------------- undeclared fields (A)

    async def _undeclared(self, target: Target, actor: Actor, scan: Scan) -> CellOutcome:
        declared = listed_properties(scan.context.document, target) or frozenset()
        path = (
            own_path(target, actor, scan.context) if path_parameters(target.path) else target.path
        )
        if path is None:
            return self._outcome(target, actor, DECLARED_ONLY, NO_RESOURCES, Verdict.SKIPPED)
        answer = await scan.control(actor, HttpMethod.GET, path)
        if answer is None:
            return self._outcome(target, actor, DECLARED_ONLY, BASELINE_FAILED, Verdict.SKIPPED)
        extra = undeclared_fields(answer.body, declared)
        if not extra:
            return self._outcome(target, actor, DECLARED_ONLY, DECLARED_ONLY, Verdict.PASS)
        detection = Detection(
            finding_type=f"property_access.{UNDECLARED}",
            severity=Severity.MEDIUM,
            owasp_category="API3:2023",
            cwe="CWE-213",
            title="La respuesta trae campos que su esquema no declara",
            recommendation=UNDECLARED_RECOMMENDATION,
            explanation=(
                f"{target.method} {target.path} devolvió a «{actor.name}» los campos "
                f"{', '.join(f'«{name}»' for name in extra)}, que el esquema de la respuesta en el "
                "contrato no declara."
            ),
            evidence=scan.requester.masker.evidence(answer, undeclared=extra),
        )
        return self._outcome(target, actor, DECLARED_ONLY, UNDECLARED, Verdict.FAIL, detection)

    # -------------------------------------------------------------- mass assignment (B)

    async def _mass_assignment(
        self, target: Target, delete: Target, actor: Actor, scan: Scan
    ) -> CellOutcome:
        document = scan.context.document
        if scan.requester.remaining < 1 + DELETE_ATTEMPTS:  # never create what it cannot delete
            return self._outcome(target, actor, REJECTED, BUDGET_RESERVED, Verdict.SKIPPED)
        protected = protected_fields(document, target, delete)
        body = {**sample_body(document, target.request_schema), **protected}
        row_id = await _note(scan, target)
        try:
            created = await scan.requester.send(
                actor,
                target.method,
                target.path,
                content=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
            )
        except LoginFailedError:
            await _mark(scan, row_id, CreatedResourceStatus.DELETED, "not_created")
            return self._outcome(target, actor, REJECTED, LOGIN_FAILED, Verdict.SKIPPED)
        except RequestFailedError:
            # It may or may not exist: the analyst checks it (created_resources).
            await _mark(scan, row_id, CreatedResourceStatus.FAILED, "no_answer")
            return self._outcome(target, actor, REJECTED, ERROR, Verdict.ERROR)
        if not 200 <= created.status_code < 300:
            await _mark(scan, row_id, CreatedResourceStatus.DELETED, "not_created")
            return self._outcome(target, actor, REJECTED, NOT_CREATED, Verdict.SKIPPED)
        location = delete_location(delete, created)
        status = await _shielded(_clean(scan, actor, row_id, location))
        accepted = accepted_fields(created.body, protected)
        if not accepted:
            return self._outcome(target, actor, REJECTED, REJECTED, Verdict.PASS)
        detection = Detection(
            finding_type="property_access.mass_assignment",
            severity=Severity.HIGH,
            owasp_category="API3:2023",
            cwe="CWE-915",
            title="La API acepta campos protegidos al crear",
            recommendation=MASS_ASSIGNMENT_RECOMMENDATION,
            explanation=(
                f"{target.method} {target.path} aceptó de «{actor.name}» los campos protegidos "
                f"{', '.join(f'«{name}»' for name in accepted)} y los devolvió con el valor "
                "enviado. El recurso de prueba se borró después."
            ),
            evidence=scan.requester.masker.evidence(
                created, accepted_fields=accepted, created_resource=status.value
            ),
        )
        return self._outcome(target, actor, REJECTED, ACCEPTED, Verdict.FAIL, detection)


# ------------------------------------------------------------------ what the contract says


def _object_schema(document: Any, schema: Any) -> dict[str, Any] | None:
    """The object schema itself, or the one of each item of a list."""
    resolved = deref(document, schema)
    if schema_type(document, resolved) == "array" and isinstance(resolved, dict):
        resolved = deref(document, resolved.get("items"))
    if isinstance(resolved, dict) and schema_type(document, resolved) == "object":
        return resolved
    return None


def properties(document: Any, schema: Any) -> dict[str, Any]:
    resolved = _object_schema(document, schema)
    found = resolved.get("properties") if resolved else None
    return {k: v for k, v in found.items() if isinstance(k, str)} if isinstance(found, dict) else {}


def listed_properties(document: Any, target: Target) -> frozenset[str] | None:
    """The fields a GET's 2xx schema enumerates, or None when it cannot be judged."""
    if target.method != HttpMethod.GET:
        return None
    resolved = _object_schema(document, target.response_schema)
    if resolved is None or not isinstance(resolved.get("properties"), dict):
        return None
    extra = resolved.get("additionalProperties")
    if extra is True or isinstance(extra, dict):  # open on purpose
        return None
    return frozenset(properties(document, target.response_schema))


def undeclared_fields(body: bytes, declared: frozenset[str]) -> list[str]:
    try:
        value = json.loads(body)
    except (ValueError, RecursionError):
        return []
    items = value if isinstance(value, list) else [value]
    seen = {key for item in items if isinstance(item, dict) for key in item}
    return sorted(seen - declared)


def delete_for(context: RunContext, target: Target) -> Target | None:
    """`DELETE /x/{id}` for `POST /x` with a JSON object body; None otherwise."""
    if target.method != HttpMethod.POST or path_parameters(target.path):
        return None
    if schema_type(context.document, target.request_schema) != "object":
        return None
    base = target.path.rstrip("/")
    return next(
        (
            t
            for t in context.targets
            if t.method == HttpMethod.DELETE
            and t.path.startswith(base + "/{")
            and len(path_parameters(t.path)) == 1
            and t.path.count("/") == base.count("/") + 1
        ),
        None,
    )


def sample(document: Any, schema: Any, depth: int = 0) -> Any:
    """A harmless valid value for a schema: its example or first enum value, else by type."""
    resolved = deref(document, schema)
    if not isinstance(resolved, dict) or depth > 5:
        return "hindama"
    if "example" in resolved:
        return resolved["example"]
    if isinstance(resolved.get("enum"), list) and resolved["enum"]:
        return resolved["enum"][0]
    kind = schema_type(document, resolved)
    formats = {
        "email": "hindama@example.invalid",
        "uuid": "00000000-0000-4000-8000-000000000000",
        "date-time": "2026-01-01T00:00:00Z",
        "date": "2026-01-01",
        "uri": "https://example.invalid/hindama",
    }
    if kind == "string":
        return formats.get(str(resolved.get("format")), "hindama")
    if kind in ("integer", "number"):
        return 1
    if kind == "boolean":
        return False
    if kind == "array":
        return []
    if kind == "object":
        return sample_body(document, resolved, depth + 1)
    return "hindama"


def sample_body(document: Any, schema: Any, depth: int = 0) -> dict[str, Any]:
    resolved = _object_schema(document, schema) or {}
    listed = resolved.get("required")
    required: list[Any] = listed if isinstance(listed, list) else []
    fields = properties(document, resolved)
    return {name: sample(document, fields.get(name), depth) for name in required if name in fields}


def protected_fields(document: Any, target: Target, delete: Target) -> dict[str, Any]:
    """The fields a client should not set, each with a recognisable value (never the id)."""
    sent = properties(document, target.request_schema)
    answered = properties(document, target.response_schema)
    identifiers = {"id", *path_parameters(delete.path)}
    names = [n for n in answered if n not in sent]
    names += [n for n, s in sent.items() if _read_only(document, s)]
    names += list(PRIVILEGE_NAMES)
    chosen: dict[str, Any] = {}
    for name in names:
        if name in identifiers or name in chosen:
            continue
        kind = schema_type(document, answered.get(name) or sent.get(name))
        if kind == "object":
            continue
        if kind == "boolean" or name in BOOLEAN_NAMES:
            chosen[name] = True
        elif kind in ("integer", "number") or name == "balance":
            chosen[name] = 999999
        elif kind == "array" or name == "permissions":
            chosen[name] = ["admin"]
        elif name == "role":
            chosen[name] = "admin"
        else:
            chosen[name] = ASSIGNED
    return chosen


def _read_only(document: Any, schema: Any) -> bool:
    resolved = deref(document, schema)
    return isinstance(resolved, dict) and resolved.get("readOnly") is True


def accepted_fields(body: bytes, protected: dict[str, Any]) -> list[str]:
    try:
        value = json.loads(body)
    except (ValueError, RecursionError):
        return []
    if not isinstance(value, dict):
        return []
    return sorted(n for n, v in protected.items() if n in value and value[n] == v)


def delete_location(delete: Target, created: Exchange) -> str | None:
    """The DELETE path of what was created: its id in the body, or the `Location` header."""
    parameter = path_parameters(delete.path)[0]
    try:
        value = json.loads(created.body)
    except (ValueError, RecursionError):
        value = None
    identifier: Any = None
    if isinstance(value, dict):
        identifier = value.get(parameter, value.get("id"))
    if identifier is None:
        header = next((v for k, v in created.response_headers if k.lower() == "location"), "")
        identifier = header.rstrip("/").rsplit("/", 1)[-1] or None
    if identifier is None or isinstance(identifier, (dict, list)):
        return None
    return fill(delete.path, {parameter: str(identifier)})


# ------------------------------------------------------------------ created resources (RN-06)


async def _note(scan: Scan, target: Target) -> UUID:
    """Before creating anything (architecture 4.3): the run can always say what it created."""
    async with scan.sessions() as session, session.begin():
        row_id = await session.scalar(
            insert(CreatedResource)
            .values(
                project_id=scan.context.project_id,
                run_id=scan.context.run_id,
                operation_id=target.id,
                location=target.path,
            )
            .returning(CreatedResource.id)
        )
    if not isinstance(row_id, UUID):  # RETURNING always gives the new row
        raise LookupError("created resource not noted")
    return row_id


async def _mark(
    scan: Scan,
    row_id: UUID,
    status: CreatedResourceStatus,
    error: str | None = None,
    location: str | None = None,
    attempts: int | None = None,
) -> None:
    values: dict[str, Any] = {"status": status, "last_error": error}
    if location is not None:
        values["location"] = location
    if attempts is not None:
        values["attempts"] = attempts
    async with scan.sessions() as session, session.begin():
        await session.execute(
            update(CreatedResource).where(CreatedResource.id == row_id).values(**values)
        )


async def _clean(
    scan: Scan, actor: Actor, row_id: UUID, location: str | None
) -> CreatedResourceStatus:
    if location is None:
        await _mark(scan, row_id, CreatedResourceStatus.FAILED, "no_identifier")
        return CreatedResourceStatus.FAILED
    await _mark(scan, row_id, CreatedResourceStatus.PENDING, location=location)
    error = "no_answer"
    for attempt in range(1, DELETE_ATTEMPTS + 1):
        try:
            answer = await scan.requester.send(actor, HttpMethod.DELETE, location)
        except (RequestFailedError, LoginFailedError):
            error = "no_answer"
            continue
        except BudgetExhaustedError:  # the reserve was taken by a concurrent cell
            error = "budget_exhausted"
            break
        if 200 <= answer.status_code < 300 or answer.status_code == 404:
            await _mark(scan, row_id, CreatedResourceStatus.DELETED, attempts=attempt)
            return CreatedResourceStatus.DELETED
        error = f"status_{answer.status_code}"
    await _mark(scan, row_id, CreatedResourceStatus.FAILED, error, attempts=DELETE_ATTEMPTS)
    return CreatedResourceStatus.FAILED


async def _shielded(step: Coroutine[Any, Any, CreatedResourceStatus]) -> CreatedResourceStatus:
    """A cancelled run still deletes what it created (RN-06)."""
    task = asyncio.ensure_future(step)
    _CLEANUPS.add(task)
    task.add_done_callback(_CLEANUPS.discard)
    return await asyncio.shield(task)
