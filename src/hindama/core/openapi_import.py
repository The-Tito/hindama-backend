"""Reading the analyst's OpenAPI 3 contract (CU-08; RF-22 to RF-25, RF-27).

The document is untrusted input. This module is pure and synchronous (the service runs it in a
thread) and never touches the network:

- **Reading:** JSON or YAML, UTF-8. YAML anchors and aliases are rejected: a few lines can expand
  exponentially when traversed ("billion laughs"), and OpenAPI documents rarely use them. Nesting is
  bounded, NUL characters are removed (PostgreSQL rejects them in text and jsonb) and non-JSON
  values (dates, NaN, non-string keys) become strings.
- **Validation:** Hindama's own rules over what it uses (OpenAPI 3.0.x/3.1.x, `info`, `paths`,
  operations, parameters, internal `$ref`). Not a full validator of the specification: a full one
  would also resolve remote references, outside the SSRF guard. Errors carry a JSON Pointer.
- **References (RF-23):** only internal ones (`#/...`). External ones are never followed and become
  `contract.external_reference` warnings. Schemas keep their `$ref`: they are not inlined, so a
  document cannot blow up in size through shared references. What each operation's schemas reach
  is fingerprinted, so a change in a shared schema still marks the operation as modified (RF-26).
- **Extraction (RF-24):** per operation, method, path, parameters (path item and operation merged),
  body, request and response schemas, and declared security.
"""

import hashlib
import json
import math
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml

MAX_DEPTH = 64
MAX_OPERATIONS = 2000
MAX_ERRORS = 20
MAX_WARNINGS = 100
MAX_REF_CHAIN = 16
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
LOCATIONS = ("path", "query", "header", "cookie")
SUPPORTED_VERSION = re.compile(r"^3\.[01]\.\d+$")
_TEMPLATE = re.compile(r"\{[^{}/]*\}")

Json = Any


# ---------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class Issue:
    """One error of the document: `field` is a JSON Pointer or «línea N»."""

    field: str | None
    code: str
    message: str


class ContractError(Exception):
    """The document is rejected: `contract.invalid` or `contract.unsupported_version` (RF-25)."""

    def __init__(self, code: str, issues: list[Issue]) -> None:
        super().__init__(code)
        self.code = code
        self.issues = issues


@dataclass(frozen=True, slots=True)
class ContractWarning:
    code: str
    message: str
    location: str | None

    def as_json(self) -> dict[str, str | None]:
        return {"code": self.code, "message": self.message, "location": self.location}


@dataclass(slots=True)
class ParsedOperation:
    method: str  # upper case
    path: str
    normalized_path: str
    operation_id: str | None
    summary: str | None
    tags: list[str]
    parameters: list[dict[str, Json]]  # name, location, required, type, schema
    request_body: dict[str, Json] | None  # required, content_types
    security: list[dict[str, str]]  # scheme, type
    schemas: dict[str, Json]  # request, responses, refs, refs_sha256


@dataclass(slots=True)
class ParsedContract:
    format: str  # json | yaml
    openapi_version: str
    api_title: str | None
    operations: list[ParsedOperation]
    warnings: list[ContractWarning] = field(default_factory=list)


def normalize_path(path: str) -> str:
    """`/users/{id}` and `/users/{userId}` are the same operation (modelo.md, operations)."""
    return _TEMPLATE.sub("{}", path)


# The last fixed segment of a login endpoint: /login, /auth/token, /api/v1/sessions...
_LOGIN_SEGMENT = re.compile(
    r"^(log-?in|sign-?in|auth|authenticate|token|tokens|session|sessions|access-?token)$",
    re.IGNORECASE,
)


def is_login_candidate(method: str, path: str) -> bool:
    """RF-30: a POST whose last fixed segment names a login. Only a proposal: the analyst confirms
    it when registering a `login` identity."""
    if method.upper() != "POST":
        return False
    segments = [s for s in path.split("/") if s and not _TEMPLATE.fullmatch(s)]
    return bool(segments) and bool(_LOGIN_SEGMENT.match(segments[-1]))


# ---------------------------------------------------------------- proposals (RF-35, RF-40)

# A fixed segment that marks an administration area: /admin/users, /internal/jobs...
_ADMIN_SEGMENT = re.compile(
    r"^(admin|admins|administration|administracion|internal|manage|management)$", re.IGNORECASE
)
# A path parameter that names an object: id, orderId, order_id, orderID.
_ID_NAME = re.compile(r"^(id|uuid|.+Id|.+ID|.+_id|.+-id)$")
MAX_NAME = 100  # name and resource_type of a ResourceParameter (contract)


def _template_name(segment: str) -> str | None:
    """`{orderId}` -> `orderId`; `None` for a fixed segment or a mixed one like `{id}.json`."""
    if _TEMPLATE.fullmatch(segment):
        return segment[1:-1]
    return None


def path_parameters(path: str) -> list[str]:
    """The names of the path's templates, in order."""
    return [segment[1:-1] for segment in _TEMPLATE.findall(path)]


def resource_parameters(path: str, parameters: list[dict[str, Json]]) -> list[dict[str, str]]:
    """RF-35: path parameters that look like object identifiers, each with the resource type of
    the fixed segment before it (`/orders/{id}` -> `orders`). Only a proposal: the analyst
    corrects it, and the types must match the ones of the registered resources."""
    declared = {
        p.get("name"): p for p in parameters if isinstance(p, dict) and p.get("location") == "path"
    }
    result: list[dict[str, str]] = []
    previous: str | None = None
    for segment in (s for s in path.split("/") if s):
        name = _template_name(segment)
        if name is None:
            previous = segment
            continue
        schema = declared.get(name, {}).get("schema")
        schema = schema if isinstance(schema, dict) else {}
        looks_like_id = (
            bool(_ID_NAME.match(name))
            or schema.get("format") == "uuid"
            or declared.get(name, {}).get("type") == "integer"
        )
        if looks_like_id and 0 < len(name) <= MAX_NAME and name.isprintable():
            base = previous if previous is not None else re.sub(r"(_|-)?(id|Id|ID)$", "", name)
            kind = (base or name).lower()[:MAX_NAME]
            if kind.isprintable() and all(r["name"] != name for r in result):
                result.append({"name": name, "resource_type": kind})
        previous = None  # /orders/{a}/{b}: b has no segment of its own
    return result


def suggested_policy(
    path: str, security: list[dict[str, str]], resources: list[dict[str, str]]
) -> str:
    """RF-40: the template the analyst will probably confirm. Never used unconfirmed (RN-08).

    - no security declared: public;
    - an administration segment: admin only;
    - the path ends in a resource identifier: owner only (`/orders/{orderId}`);
    - anything else (collections, `/me`): any authenticated user.
    """
    if not security:
        return "public"
    segments = [s for s in path.split("/") if s]
    if any(_ADMIN_SEGMENT.match(s) for s in segments if _template_name(s) is None):
        return "admin_only"
    last = _template_name(segments[-1]) if segments else None
    if last is not None and any(r["name"] == last for r in resources):
        return "owner_only"
    return "authenticated"


def pointer(*parts: str | int) -> str:
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def invalid(field: str | None, code: str, message: str) -> ContractError:
    return ContractError("contract.invalid", [Issue(field, code, message)])


# ---------------------------------------------------------------- reading


def read_document(raw: bytes) -> tuple[str, Json]:
    """The document as JSON values, and its format."""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise invalid(None, "contract.encoding", "El documento debe estar en UTF-8.") from None
    if not text.strip():
        raise invalid(None, "contract.empty", "El documento está vacío.")
    try:
        if text.lstrip()[0] in "{[":
            fmt, value = "json", _load_json(text)
        else:
            fmt, value = "yaml", _load_yaml(text)
        return fmt, _normalize(value, 0)
    except RecursionError:
        raise _too_deep() from None


def _too_deep() -> ContractError:
    return invalid(None, "contract.too_deep", f"El documento anida más de {MAX_DEPTH} niveles.")


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def _load_json(text: str) -> Json:
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as error:
        raise invalid(
            f"línea {error.lineno}",
            "contract.invalid_json",
            f"El JSON no es válido (columna {error.colno}).",
        ) from None
    except ValueError as error:  # NaN, Infinity: not JSON, and PostgreSQL rejects them in jsonb
        raise invalid(
            None, "contract.invalid_json", f"El JSON contiene un valor no permitido: {error}."
        ) from None


def _load_yaml(text: str) -> Json:
    try:
        for event in yaml.parse(text, Loader=yaml.CSafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise invalid(
                    f"línea {event.start_mark.line + 1}",
                    "contract.yaml_alias",
                    "No se admiten anclas ni alias de YAML (& y *). Escribe el contenido completo.",
                )
        return yaml.load(text, Loader=yaml.CSafeLoader)
    except yaml.MarkedYAMLError as error:
        mark = error.problem_mark or error.context_mark
        line = f"línea {mark.line + 1}" if mark else None
        raise invalid(
            line, "contract.invalid_yaml", "El YAML no es válido en esta línea."
        ) from None
    except yaml.YAMLError:
        raise invalid(None, "contract.invalid_yaml", "El YAML no es válido.") from None


def _clean(text: str) -> str:
    return text.replace("\x00", "")


def _key(key: object) -> str:
    if isinstance(key, str):
        return _clean(key)
    if isinstance(key, bool):
        return "true" if key else "false"
    return _clean(str(key))  # YAML reads `200:` as an integer: the status code as text


def _normalize(value: object, depth: int) -> Json:
    if depth > MAX_DEPTH:
        raise _too_deep()
    if isinstance(value, dict):
        return {_key(k): _normalize(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v, depth + 1) for v in value]
    if isinstance(value, str):
        return _clean(value)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, bytes):
        return _clean(value.decode("utf-8", errors="replace"))
    return _clean(str(value))


# ---------------------------------------------------------------- analysis


class _Missing:
    pass


MISSING = _Missing()


def _unescape(part: str) -> str:
    return unquote(part).replace("~1", "/").replace("~0", "~")


class _Analysis:
    def __init__(self, root: dict[str, Json], base_host: str) -> None:
        self.root = root
        self.base_host = base_host.lower()
        self.issues: list[Issue] = []
        self.warnings: list[ContractWarning] = []
        self._warned: set[tuple[str, str | None]] = set()
        self._direct_refs: dict[str, list[str]] = {}
        self._digests: dict[str, str] = {}
        schemes = root.get("components", {})
        self.security_schemes = (
            schemes.get("securitySchemes", {}) if isinstance(schemes, dict) else {}
        )
        if not isinstance(self.security_schemes, dict):
            self.security_schemes = {}

    # ------------------------------------------------------------ reporting

    def error(self, location: str | None, code: str, message: str) -> None:
        if len(self.issues) < MAX_ERRORS:
            self.issues.append(Issue(location, code, message))

    def warn(self, code: str, message: str, location: str | None) -> None:
        if (code, location) in self._warned or len(self.warnings) >= MAX_WARNINGS:
            return
        self._warned.add((code, location))
        self.warnings.append(ContractWarning(code, message, location))

    # ------------------------------------------------------------ references

    def lookup(self, ref: str) -> Json:
        node: Json = self.root
        if ref in ("#", "#/"):
            return node
        for raw in ref.removeprefix("#/").split("/"):
            part = _unescape(raw)
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                return MISSING
        return node

    def resolve(self, node: Json, location: str) -> tuple[Json, str, bool] | None:
        """Follows the `$ref` of an object (parameter, body, response, path item).

        Returns the object, where it lives and whether it was inline; `None` if the reference is
        external (a warning) or broken (an error).
        """
        seen: set[str] = set()
        inline = True
        while isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str):
                self.error(location + "/$ref", "contract.invalid_type", "`$ref` debe ser texto.")
                return None
            if not ref.startswith("#"):
                self._external(location + "/$ref")
                return None
            if ref in seen or len(seen) >= MAX_REF_CHAIN:
                self.error(location, "contract.circular_reference", "La referencia es circular.")
                return None
            seen.add(ref)
            target = self.lookup(ref)
            if target is MISSING:
                self.error(
                    location + "/$ref",
                    "contract.unresolved_reference",
                    f"La referencia {ref} no existe en el documento.",
                )
                return None
            node, location, inline = target, ref[1:], False
        return node, location, inline

    def _external(self, location: str) -> None:
        self.warn(
            "contract.external_reference",
            "No se siguió una referencia a un archivo o URL externos.",
            location,
        )

    def _refs_in(self, node: Json, location: str) -> Iterator[str]:
        """Internal `$ref` targets inside a schema; reports external and broken ones."""
        stack = [(node, location)]
        while stack:
            current, where = stack.pop()
            if isinstance(current, dict):
                ref = current.get("$ref")
                if isinstance(ref, str):
                    if not ref.startswith("#"):
                        self._external(where + "/$ref")
                    elif self.lookup(ref) is MISSING:
                        self.error(
                            where + "/$ref",
                            "contract.unresolved_reference",
                            f"La referencia {ref} no existe en el documento.",
                        )
                    else:
                        yield ref
                stack.extend((v, where + pointer(k)) for k, v in current.items() if k != "$ref")
            elif isinstance(current, list):
                stack.extend((v, where + pointer(i)) for i, v in enumerate(current))

    def _direct(self, ref: str) -> list[str]:
        if ref not in self._direct_refs:
            self._direct_refs[ref] = []  # a cycle reaches this entry while it is being filled
            self._direct_refs[ref] = sorted(set(self._refs_in(self.lookup(ref), ref[1:])))
        return self._direct_refs[ref]

    def _digest(self, ref: str) -> str:
        if ref not in self._digests:
            content = json.dumps(self.lookup(ref), sort_keys=True, ensure_ascii=False)
            self._digests[ref] = hashlib.sha256(content.encode()).hexdigest()
        return self._digests[ref]

    def closure(self, roots: list[tuple[Json, str]]) -> list[str]:
        """Every definition the given schemas reach, transitively."""
        pending = sorted({ref for node, where in roots for ref in self._refs_in(node, where)})
        reached: set[str] = set()
        while pending:
            ref = pending.pop()
            if ref not in reached:
                reached.add(ref)
                pending.extend(self._direct(ref))
        return sorted(reached)

    def fingerprint(self, refs: list[str]) -> str:
        joined = "\n".join(f"{ref} {self._digest(ref)}" for ref in refs)
        return hashlib.sha256(joined.encode()).hexdigest()


# ---------------------------------------------------------------- entry point


def parse_contract(raw: bytes, base_host: str) -> ParsedContract:
    """Reads, validates and extracts the contract. Raises `ContractError`."""
    fmt, root = read_document(raw)
    if not isinstance(root, dict):
        raise invalid("/", "contract.invalid_type", "El documento debe ser un objeto.")
    version = _version(root)
    analysis = _Analysis(root, base_host)
    title = _info(analysis)
    operations = _paths(analysis, version)
    _servers(analysis)
    if isinstance(root.get("webhooks"), dict) and root["webhooks"]:
        analysis.warn(
            "contract.unparsed_element", "Hindama no prueba los webhooks del contrato.", "/webhooks"
        )
    if analysis.issues:
        raise ContractError("contract.invalid", analysis.issues)
    return ParsedContract(fmt, version, title, operations, analysis.warnings)


def _version(root: dict[str, Json]) -> str:
    if "swagger" in root:
        raise ContractError(
            "contract.unsupported_version",
            [
                Issue(
                    "/swagger",
                    "contract.unsupported_version",
                    "Swagger 2 no está soportado. Conviértelo a OpenAPI 3.",
                )
            ],
        )
    if "openapi" not in root:
        raise invalid("/openapi", "contract.required_field", "Falta el campo `openapi`.")
    version = str(root["openapi"])
    if not SUPPORTED_VERSION.match(version):
        raise ContractError(
            "contract.unsupported_version",
            [
                Issue(
                    "/openapi",
                    "contract.unsupported_version",
                    "Solo se admiten OpenAPI 3.0 y 3.1.",
                )
            ],
        )
    return version


def _info(analysis: _Analysis) -> str | None:
    info = analysis.root.get("info")
    if not isinstance(info, dict):
        analysis.error("/info", "contract.required_field", "Falta el objeto `info`.")
        return None
    title = info.get("title")
    if not isinstance(title, str):
        analysis.error("/info/title", "contract.required_field", "Falta `info.title`.")
        title = None
    if info.get("version") is None or isinstance(info.get("version"), dict | list):
        analysis.error("/info/version", "contract.required_field", "Falta `info.version`.")
    return title


def _servers(analysis: _Analysis) -> None:
    """RF-27: servers on another host are reported; tests always use the project's base URL."""
    candidates: list[tuple[Json, str]] = [(analysis.root.get("servers"), "/servers")]
    paths = analysis.root.get("paths")
    if isinstance(paths, dict):
        for path, item in paths.items():
            if isinstance(item, dict):
                candidates.append((item.get("servers"), pointer("paths", path, "servers")))
                for method in METHODS:
                    operation = item.get(method)
                    if isinstance(operation, dict):
                        candidates.append(
                            (operation.get("servers"), pointer("paths", path, method, "servers"))
                        )
    for servers, location in candidates:
        if not isinstance(servers, list):
            continue
        for index, server in enumerate(servers):
            if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                continue
            host = _server_host(server)
            if host is not None and host != analysis.base_host:
                analysis.warn(
                    "contract.servers_mismatch",
                    "Los servidores del contrato no coinciden con la URL base; se usará la URL "
                    "base del proyecto.",
                    f"{location}/{index}/url",
                )


def _server_host(server: dict[str, Json]) -> str | None:
    """The host of an absolute server URL, with its variables at their defaults; `None` if the
    URL is relative (it then lives on the base URL) or the host cannot be known."""
    url: str = server["url"]
    variables = server.get("variables")
    if isinstance(variables, dict):
        for name, variable in variables.items():
            if isinstance(variable, dict) and isinstance(variable.get("default"), str):
                url = url.replace("{" + name + "}", variable["default"])
    if "://" not in url:
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host or "{" in host:
        return None
    return host.lower()


# ---------------------------------------------------------------- paths and operations


def _paths(analysis: _Analysis, version: str) -> list[ParsedOperation]:
    paths = analysis.root.get("paths")
    if paths is None:
        if version.startswith("3.0"):
            analysis.error("/paths", "contract.required_field", "Falta el objeto `paths`.")
        return []
    if not isinstance(paths, dict):
        analysis.error("/paths", "contract.invalid_type", "`paths` debe ser un objeto.")
        return []
    operations: list[ParsedOperation] = []
    seen: dict[tuple[str, str], str] = {}
    for path, raw_item in paths.items():
        if path.startswith("x-"):
            continue
        location = pointer("paths", path)
        if not path.startswith("/"):
            analysis.error(location, "contract.invalid_value", "La ruta debe empezar con «/».")
            continue
        resolved = analysis.resolve(raw_item, location)
        if resolved is None:
            continue
        item, item_location, _ = resolved
        if not isinstance(item, dict):
            analysis.error(location, "contract.invalid_type", "La ruta debe ser un objeto.")
            continue
        shared = _parameter_list(analysis, item.get("parameters"), item_location + "/parameters")
        for method in METHODS:
            if method not in item:
                continue
            op_location = f"{item_location}/{method}"
            operation = item[method]
            if not isinstance(operation, dict):
                analysis.error(
                    op_location, "contract.invalid_type", "La operación debe ser un objeto."
                )
                continue
            key = (method, normalize_path(path))
            if key in seen:
                analysis.error(
                    op_location,
                    "contract.duplicate_operation",
                    f"Repite la operación {method.upper()} {seen[key]}: las rutas solo difieren "
                    "en el nombre de un parámetro.",
                )
                continue
            seen[key] = path
            if len(operations) >= MAX_OPERATIONS:
                analysis.error(
                    "/paths",
                    "contract.too_many_operations",
                    f"El contrato tiene más de {MAX_OPERATIONS} operaciones.",
                )
                return operations
            operations.append(
                _operation(analysis, version, method, path, operation, op_location, shared)
            )
    return operations


@dataclass(slots=True)
class _Parameter:
    name: str
    location: str
    required: bool
    type: str | None
    schema: Json
    schema_location: str | None  # for the closure; None when stored as a reference


def _parameter_list(analysis: _Analysis, raw: Json, location: str) -> list[_Parameter]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        analysis.error(location, "contract.invalid_type", "`parameters` debe ser una lista.")
        return []
    result = []
    for index, entry in enumerate(raw):
        parameter = _parameter(analysis, entry, f"{location}/{index}")
        if parameter is not None:
            result.append(parameter)
    return result


def _parameter(analysis: _Analysis, entry: Json, location: str) -> _Parameter | None:
    resolved = analysis.resolve(entry, location)
    if resolved is None:
        return None
    node, where, inline = resolved
    if not isinstance(node, dict):
        analysis.error(location, "contract.invalid_type", "El parámetro debe ser un objeto.")
        return None
    name, place = node.get("name"), node.get("in")
    if not isinstance(name, str) or not name:
        analysis.error(where + "/name", "contract.required_field", "Falta el nombre del parámetro.")
        return None
    if place not in LOCATIONS:
        analysis.error(
            where + "/in",
            "contract.invalid_value",
            "`in` debe ser path, query, header o cookie.",
        )
        return None
    schema = node.get("schema")
    schema_location = where + "/schema"
    if schema is None and isinstance(node.get("content"), dict) and node["content"]:
        media, media_object = next(iter(node["content"].items()))
        if isinstance(media_object, dict):
            schema = media_object.get("schema")
            schema_location = where + pointer("content", media, "schema")
    return _Parameter(
        name=name,
        location=place,
        required=place == "path" or node.get("required") is True,
        type=_schema_type(analysis, schema),
        schema=_stored_schema(schema, schema_location, inline),
        schema_location=schema_location if inline and schema is not None else None,
    )


def _schema_type(analysis: _Analysis, schema: Json) -> str | None:
    if isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
        target = analysis.lookup(schema["$ref"]) if schema["$ref"].startswith("#") else MISSING
        schema = target if isinstance(target, dict) else {}
    if not isinstance(schema, dict):
        return None
    kind = schema.get("type")
    if isinstance(kind, list):  # 3.1: ["string", "null"]
        kind = next((k for k in kind if isinstance(k, str) and k != "null"), None)
    return kind if isinstance(kind, str) else None


def _stored_schema(schema: Json, location: str, inline: bool) -> Json:
    """Inline schemas are stored as they are; one inside a referenced component is stored as a
    reference to it, so a shared component is never copied into every operation."""
    if schema is None or inline:
        return schema
    return {"$ref": "#" + location}


def _operation(
    analysis: _Analysis,
    version: str,
    method: str,
    path: str,
    operation: dict[str, Json],
    location: str,
    shared: list[_Parameter],
) -> ParsedOperation:
    own = _parameter_list(analysis, operation.get("parameters"), location + "/parameters")
    merged = {(p.name, p.location): p for p in shared}
    merged.update({(p.name, p.location): p for p in own})  # the operation's own wins
    parameters = list(merged.values())

    roots: list[tuple[Json, str]] = [
        (p.schema, p.schema_location or "") for p in parameters if p.schema is not None
    ]
    request_body, request_schemas = _request_body(
        analysis, operation.get("requestBody"), location + "/requestBody", roots
    )
    responses = _responses(analysis, version, operation.get("responses"), location, roots)
    if "callbacks" in operation:
        analysis.warn(
            "contract.unparsed_element",
            "Hindama no prueba los callbacks de una operación.",
            location + "/callbacks",
        )
    refs = analysis.closure(roots)
    tags = operation.get("tags")
    return ParsedOperation(
        method=method.upper(),
        path=path,
        normalized_path=normalize_path(path),
        operation_id=_text(operation.get("operationId")),
        summary=_text(operation.get("summary")),
        tags=[t for t in tags if isinstance(t, str)] if isinstance(tags, list) else [],
        parameters=[
            {
                "name": p.name,
                "location": p.location,
                "required": p.required,
                "type": p.type,
                "schema": p.schema,
            }
            for p in parameters
        ],
        request_body=request_body,
        security=_security(analysis, operation, location),
        schemas={
            "request": request_schemas,
            "responses": responses,
            "refs": refs,
            "refs_sha256": analysis.fingerprint(refs),
        },
    )


def _text(value: Json) -> str | None:
    return value if isinstance(value, str) else None


def _content_schemas(
    content: Json, where: str, inline: bool, roots: list[tuple[Json, str]]
) -> dict[str, Json]:
    result: dict[str, Json] = {}
    if not isinstance(content, dict):
        return result
    for media, media_object in content.items():
        schema = media_object.get("schema") if isinstance(media_object, dict) else None
        schema_location = where + pointer("content", media, "schema")
        result[media] = _stored_schema(schema, schema_location, inline)
        if schema is not None and inline:
            roots.append((schema, schema_location))
        elif schema is not None:
            roots.append((result[media], schema_location))
    return result


def _request_body(
    analysis: _Analysis, raw: Json, location: str, roots: list[tuple[Json, str]]
) -> tuple[dict[str, Json] | None, dict[str, Json]]:
    if raw is None:
        return None, {}
    resolved = analysis.resolve(raw, location)
    if resolved is None:
        return None, {}
    node, where, inline = resolved
    if not isinstance(node, dict) or not isinstance(node.get("content"), dict):
        analysis.error(location, "contract.required_field", "El cuerpo debe declarar `content`.")
        return None, {}
    schemas = _content_schemas(node["content"], where, inline, roots)
    body = {"required": node.get("required") is True, "content_types": sorted(node["content"])}
    return body, schemas


def _responses(
    analysis: _Analysis,
    version: str,
    raw: Json,
    location: str,
    roots: list[tuple[Json, str]],
) -> dict[str, Json]:
    where = location + "/responses"
    if raw is None or (isinstance(raw, dict) and not raw):
        if version.startswith("3.0"):
            analysis.error(where, "contract.required_field", "La operación no declara respuestas.")
        return {}
    if not isinstance(raw, dict):
        analysis.error(where, "contract.invalid_type", "`responses` debe ser un objeto.")
        return {}
    result: dict[str, Json] = {}
    for status, response in raw.items():
        if status.startswith("x-"):
            continue
        resolved = analysis.resolve(response, where + pointer(status))
        if resolved is None:
            continue
        node, node_where, inline = resolved
        if not isinstance(node, dict):
            analysis.error(
                where + pointer(status), "contract.invalid_type", "La respuesta debe ser un objeto."
            )
            continue
        result[status] = _content_schemas(node.get("content"), node_where, inline, roots)
    return result


_HTTP_SCHEMES = {"bearer": "http_bearer", "basic": "http_basic"}
_SCHEME_TYPES = {"apiKey": "api_key", "oauth2": "oauth2", "openIdConnect": "openid_connect"}


def _security(
    analysis: _Analysis, operation: dict[str, Json], location: str
) -> list[dict[str, str]]:
    """The operation's requirements, or the document's; `[]` means public by the contract."""
    requirements = operation.get("security", analysis.root.get("security", []))
    if not isinstance(requirements, list):
        return []
    names: list[str] = []
    for requirement in requirements:
        if isinstance(requirement, dict):
            names.extend(name for name in requirement if name not in names)
    result = []
    for name in names:
        scheme = analysis.security_schemes.get(name)
        if not isinstance(scheme, dict):
            analysis.warn(
                "contract.unparsed_element",
                f"El esquema de seguridad «{name}» no está declarado en "
                "components.securitySchemes.",
                location + "/security",
            )
            kind = "other"
        elif scheme.get("type") == "http":
            kind = _HTTP_SCHEMES.get(str(scheme.get("scheme", "")).lower(), "other")
        else:
            kind = _SCHEME_TYPES.get(str(scheme.get("type")), "other")
        result.append({"scheme": name, "type": kind})
    return result
