"""Builds the Postman collection and its local environment from the contract (postman/README.md).

    uv run python -m postman.build [--contract ../hindama-docs/03-api/openapi.yaml]

Two parts:

- **One folder per tag,** with every operation of the contract: path, query and header
  parameters, the body of each request example (or one built from the schema) and the response
  examples, so the contract can be read from Postman.
- **«Flujo con el laboratorio»:** the lab project of the integration tests, step by step through
  the API, with the same policies, identities and resources (`tests/lab/scanning.py`). Each step
  saves the ids the next ones need.

The collection gets the Cognito access token by itself (USER_PASSWORD_AUTH with SECRET_HASH) and
keeps it in the environment. No secret is written here: they live only in the Postman
environment, as secret variables the analyst fills.
"""

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import yaml
from tests.lab.app import ANA_PASSWORD, BETO_TOKEN, RAIZ_TOKEN
from tests.lab.scanning import POLICIES, RESOURCES

HERE = Path(__file__).parent
DEFAULT_CONTRACT = HERE.parent.parent / "hindama-docs" / "03-api" / "openapi.yaml"
SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"

# Path parameters become collection variables, so one request feeds the next.
PATH_VARIABLES = {
    "project_id",
    "contract_id",
    "operation_id",
    "identity_id",
    "resource_id",
    "run_id",
    "finding_id",
}

# After a 2xx, what the generic folders keep for the next request: variable <- JS expression.
CAPTURES = {
    "createProject": {"project_id": "body.id"},
    "importContract": {"contract_id": "body.id"},
    "listOperations": {"operation_id": "body.items[0] && body.items[0].id"},
    "createIdentity": {"identity_id": "body.id"},
    "createResource": {"resource_id": "body.id"},
    "createRun": {"run_id": "body.id"},
    "listFindings": {"finding_id": "body.items[0] && body.items[0].id"},
}

AUTH_SCRIPT = """\
// Gets a Cognito access token (USER_PASSWORD_AUTH) when there is none or it expires in < 1 min.
// The API accepts only access tokens of the configured client (core/auth.py).
const NO_AUTH = %(no_auth)s;
const path = '/' + pm.request.url.path.join('/');
if (!NO_AUTH.includes(path)) {
  const env = (name) => pm.environment.get(name);
  const expiresAt = Number(env('tokenExpiresAt') || 0);
  if (!env('accessToken') || Date.now() > expiresAt - 60000) {
    const required = ['cognitoRegion', 'cognitoClientId', 'cognitoClientSecret', 'username',
      'password'];
    const missing = required.filter((name) => !env(name));
    if (missing.length) {
      throw new Error('Faltan variables del entorno: ' + missing.join(', '));
    }
    const CryptoJS = require('crypto-js');
    const message = env('username') + env('cognitoClientId');
    const secretHash = CryptoJS.HmacSHA256(message, env('cognitoClientSecret'))
      .toString(CryptoJS.enc.Base64);
    pm.sendRequest({
      url: 'https://cognito-idp.' + env('cognitoRegion') + '.amazonaws.com/',
      method: 'POST',
      header: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.InitiateAuth',
      },
      body: {
        mode: 'raw',
        raw: JSON.stringify({
          AuthFlow: 'USER_PASSWORD_AUTH',
          ClientId: env('cognitoClientId'),
          AuthParameters: {
            USERNAME: env('username'),
            PASSWORD: env('password'),
            SECRET_HASH: secretHash,
          },
        }),
      },
    }, (error, response) => {
      if (error) { throw error; }
      const body = response.json();
      if (!body.AuthenticationResult) {
        // NEW_PASSWORD_REQUIRED: fix it with admin-set-user-password --permanent (README).
        const reason = body.ChallengeName || body.message || response.code;
        throw new Error('Cognito no entregó token: ' + reason);
      }
      pm.environment.set('accessToken', body.AuthenticationResult.AccessToken);
      const lifetime = body.AuthenticationResult.ExpiresIn * 1000;
      pm.environment.set('tokenExpiresAt', String(Date.now() + lifetime));
    });
  }
}
"""


# ------------------------------------------------------------------ contract helpers


class Contract:
    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document

    def resolve(self, node: Any) -> Any:
        while isinstance(node, dict) and "$ref" in node:
            target: Any = self.document
            for part in node["$ref"].removeprefix("#/").split("/"):
                target = target[part]
            node = target
        return node

    def sample(self, schema: Any, name: str = "", depth: int = 0) -> Any:
        """A plausible value for a schema without an example: what Postman shows as the body."""
        schema = self.resolve(schema)
        if name in PATH_VARIABLES:
            return "{{" + name + "}}"
        for key in ("example", "default", "const"):
            if key in schema:
                return schema[key]
        if schema.get("examples"):
            return schema["examples"][0]
        if schema.get("enum"):
            return schema["enum"][0]
        if "allOf" in schema:
            merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
            for part in schema["allOf"]:
                part = self.resolve(part)
                merged["properties"].update(part.get("properties", {}))
                merged["required"] += part.get("required", [])
            return self.sample(merged, name, depth)
        for key in ("oneOf", "anyOf"):
            if key in schema:
                options = [self.resolve(o) for o in schema[key]]
                options = [o for o in options if o.get("type") != "null"] or options
                return self.sample(options[0], name, depth)
        kind = schema.get("type", "object")
        if isinstance(kind, list):
            kind = next((k for k in kind if k != "null"), "null")
        if depth > 6:
            return None
        if kind == "object":
            properties = schema.get("properties", {})
            keep = schema.get("required") or list(properties)
            return {k: self.sample(properties[k], k, depth + 1) for k in keep if k in properties}
        if kind == "array":
            return [self.sample(schema.get("items", {}), name, depth + 1)]
        if kind in ("integer", "number"):
            return schema.get("minimum", 1)
        if kind == "boolean":
            return False
        if kind == "null":
            return None
        return {
            "uuid": "00000000-0000-0000-0000-000000000000",
            "date-time": "2026-11-18T00:00:00Z",
            "uri": "https://api.ejemplo.com",
            "email": "analista@ejemplo.com",
        }.get(schema.get("format", ""), "texto")

    def examples(self, media: dict[str, Any]) -> list[tuple[str, Any]]:
        """`(name, value)` of a media type's examples, in the contract's order."""
        if "examples" in media:
            found = []
            for key, example in media["examples"].items():
                example = self.resolve(example)
                found.append((example.get("summary", key), example.get("value")))
            return found
        if "example" in media:
            return [("Ejemplo", media["example"])]
        return []


def url(path: str, query: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    path, _, query_string = path.partition("?")
    if query_string:
        query = [
            {"key": key, "value": value}
            for key, _, value in (pair.partition("=") for pair in query_string.split("&"))
        ]
    templated = path
    for name in PATH_VARIABLES:
        templated = templated.replace("{" + name + "}", "{{" + name + "}}")
    parts = [p for p in templated.split("/") if p]
    raw = "{{baseUrl}}/" + "/".join(parts)
    enabled = [q for q in query or [] if not q.get("disabled")]
    if enabled:
        raw += "?" + "&".join(f"{q['key']}={q['value']}" for q in enabled)
    result: dict[str, Any] = {"raw": raw, "host": ["{{baseUrl}}"], "path": parts}
    if query:
        result["query"] = query
    return result


def capture_script(captures: dict[str, str], extra: str = "") -> list[dict[str, Any]]:
    lines = [
        "if (pm.response.code < 300 && pm.response.text()) {",
        "  const body = pm.response.json();",
    ]
    for variable, expression in captures.items():
        lines += [
            f"  const {variable} = {expression};",
            f"  if ({variable}) {{ pm.collectionVariables.set('{variable}', {variable}); }}",
        ]
    if extra:
        lines += ["  " + line for line in extra.splitlines()]
    lines.append("}")
    return [{"listen": "test", "script": {"type": "text/javascript", "exec": lines}}]


def json_body(value: Any) -> dict[str, Any]:
    return {
        "mode": "raw",
        "raw": json.dumps(value, indent=2, ensure_ascii=False),
        "options": {"raw": {"language": "json"}},
    }


# ------------------------------------------------------------------ the contract's folders


def operation_items(contract: Contract, path: str, method: str, op: dict[str, Any]) -> list[Any]:
    parameters = [contract.resolve(p) for p in op.get("parameters", [])]
    query: list[dict[str, Any]] = []
    headers: list[dict[str, Any]] = []
    for p in parameters:
        schema = contract.resolve(p.get("schema", {}))
        entry = {
            "key": p["name"],
            "value": str(contract.sample(schema, p["name"])),
            "description": (
                ("Obligatorio. " if p.get("required") else "") + p.get("description", "")
            ).strip(),
            "disabled": not p.get("required", False),
        }
        (query if p["in"] == "query" else headers if p["in"] == "header" else []).append(entry)

    responses = []
    for status, response in op.get("responses", {}).items():
        response = contract.resolve(response)
        for media_type, media in response.get("content", {}).items():
            for name, value in contract.examples(media):
                responses.append((status, f"{status} {name}", media_type, value))
            if not contract.examples(media) and "schema" in media and media_type.endswith("json"):
                value = contract.sample(media["schema"])
                responses.append(
                    (
                        status,
                        f"{status} {response.get('description', '')}".strip(),
                        media_type,
                        value,
                    )
                )

    docs = [op.get("description", "").strip(), "", "**Respuestas:**"]
    for status, response in op.get("responses", {}).items():
        docs.append(f"- `{status}`: {contract.resolve(response).get('description', '')}")

    bodies: list[tuple[str, dict[str, Any] | None]] = [("", None)]
    content = contract.resolve(op.get("requestBody", {})).get("content", {})
    if "application/json" in content:
        media = content["application/json"]
        found = contract.examples(media) or [("", contract.sample(media.get("schema", {})))]
        bodies = [(name, json_body(value)) for name, value in found]
    elif "multipart/form-data" in content:
        schema = contract.resolve(content["multipart/form-data"]["schema"])
        form = []
        for key, prop in schema.get("properties", {}).items():
            prop = contract.resolve(prop)
            entry = {"key": key, "description": prop.get("description", "")}
            if prop.get("format") == "binary":
                entry |= {"type": "file", "src": [], "disabled": True}
            else:
                entry |= {"type": "text", "value": "https://api.ejemplo.com/openapi.json"}
            form.append(entry)
        bodies = [("", {"mode": "formdata", "formdata": form})]
        headers = [h for h in headers if h["key"].lower() != "content-type"]

    items = []
    for name, body in bodies:
        title = op.get("summary", op["operationId"])
        if len(bodies) > 1:
            title += f" — {name}"
        request: dict[str, Any] = {
            "method": method.upper(),
            "header": headers
            + (
                [{"key": "Content-Type", "value": "application/json"}]
                if body and body["mode"] == "raw"
                else []
            ),
            "url": url(path, query),
            "description": f"`{op['operationId']}`\n\n" + "\n".join(docs),
        }
        if body is not None:
            request["body"] = body
        if op.get("security") == []:
            request["auth"] = {"type": "noauth"}
        item: dict[str, Any] = {
            "name": title,
            "request": request,
            "response": [
                {
                    "name": label,
                    "originalRequest": copy.deepcopy(
                        {k: v for k, v in request.items() if k != "description"}
                    ),
                    "status": label,
                    "code": int(status) if status.isdigit() else 200,
                    "_postman_previewlanguage": "json",
                    "header": [{"key": "Content-Type", "value": media_type}],
                    "body": json.dumps(value, indent=2, ensure_ascii=False),
                }
                for status, label, media_type, value in responses
            ],
        }
        if op["operationId"] in CAPTURES:
            item["event"] = capture_script(CAPTURES[op["operationId"]])
        items.append(item)
    return items


def contract_folders(contract: Contract) -> list[dict[str, Any]]:
    folders: dict[str, list[Any]] = {}
    tag_docs = {t["name"]: t.get("description", "") for t in contract.document.get("tags", [])}
    for path, path_item in contract.document["paths"].items():
        for method, op in path_item.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            tag = (op.get("tags") or ["Otros"])[0]
            folders.setdefault(tag, []).extend(operation_items(contract, path, method, op))
    return [
        {"name": tag, "description": tag_docs.get(tag, ""), "item": items}
        for tag, items in folders.items()
    ]


# ------------------------------------------------------------------ the lab flow


def step(
    name: str,
    method: str,
    path: str,
    description: str,
    body: Any = None,
    form: list[dict[str, Any]] | None = None,
    captures: dict[str, str] | None = None,
    extra: str = "",
    auth: bool = True,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "method": method,
        "header": [],
        "url": url(path),
        "description": description,
    }
    if body is not None:
        request["body"] = json_body(body)
        request["header"] = [{"key": "Content-Type", "value": "application/json"}]
    if form is not None:
        request["body"] = {"mode": "formdata", "formdata": form}
    if not auth:
        request["auth"] = {"type": "noauth"}
    item: dict[str, Any] = {"name": name, "request": request}
    if captures or extra:
        item["event"] = capture_script(captures or {}, extra)
    return item


def policy_variable(policy: str, owner_field: str | None) -> str:
    return "ops_" + policy + ("_" + owner_field if owner_field else "")


def lab_flow() -> dict[str, Any]:
    p = "/projects/{project_id}"
    groups: dict[tuple[str, str | None], list[str]] = {}
    for key, rule in POLICIES.items():
        groups.setdefault(rule, []).append(key)

    group_script = [
        "const ids = Object.fromEntries(body.items.map((o) => [o.method + ' ' + o.path, o.id]));",
        "pm.collectionVariables.set('op_login', ids['POST /auth/login']);",
    ]
    for (policy, owner_field), keys in groups.items():
        group_script.append(
            f"pm.collectionVariables.set('{policy_variable(policy, owner_field)}', "
            f"JSON.stringify({json.dumps(keys)}.map((k) => ids[k])));"
        )

    steps = [
        step(
            "00 Salud de la API",
            "GET",
            "/health",
            "Sin token. Comprueba que la API responde.",
            auth=False,
        ),
        step(
            "01 Mi cuenta",
            "GET",
            "/me",
            "Usa el token de Cognito. Guarda la versión vigente de los términos.",
            captures={"terms_version": "body.terms.current_version"},
        ),
        step(
            "02 Aceptar términos",
            "POST",
            "/me/terms",
            "RF-04. Sin esto no se pueden crear proyectos.",
            body={"version": "{{terms_version}}"},
        ),
        step(
            "03 Crear proyecto del laboratorio",
            "POST",
            "/projects",
            "La URL base es la del túnel (`labUrl`), nunca localhost: la guardia SSRF bloquea "
            "loopback.",
            body={
                "name": "Laboratorio",
                "description": "Mini API del laboratorio por túnel",
                "base_url": "{{labUrl}}",
            },
            captures={"project_id": "body.id"},
        ),
        step(
            "04 Ver código de verificación",
            "GET",
            p + "/verification",
            "Copia el código a `tests/lab/.verificacion.txt` (la consola de Postman muestra el "
            "comando).",
            captures={"verification_code": "body.code"},
            extra="console.log(`echo '${body.code}' > tests/lab/.verificacion.txt`);",
        ),
        step(
            "05 Verificar propiedad por archivo",
            "POST",
            p + "/verification",
            "RF-18. Lee `/.well-known/hindama-verificacion.txt` del laboratorio.",
            body={"method": "file"},
        ),
        step(
            "06 Importar contrato del laboratorio",
            "POST",
            p + "/contracts",
            "Por URL: el laboratorio publica su OpenAPI en `/openapi.json`.",
            form=[{"key": "url", "value": "{{labUrl}}/openapi.json", "type": "text"}],
            captures={"contract_id": "body.id"},
        ),
        step(
            "07 Listar operaciones",
            "GET",
            p + "/operations?page_size=100",
            "Guarda los ids por grupo de política para los pasos 08.",
            extra="\n".join(group_script),
        ),
    ]
    for (policy, owner_field), keys in groups.items():
        body = {"operation_ids": "__IDS__", "policy": policy}
        if owner_field:
            body["owner_field"] = owner_field
        item = step(
            f"08 Política {policy}" + (f" ({owner_field})" if owner_field else ""),
            "POST",
            p + "/policy",
            "Operaciones: " + ", ".join(keys),
            body=body,
        )
        item["request"]["body"]["raw"] = item["request"]["body"]["raw"].replace(
            '"__IDS__"', "{{" + policy_variable(policy, owner_field) + "}}"
        )
        steps.append(item)

    identities = [
        (
            "ana",
            {
                "name": "ana",
                "role": "user",
                "auth_type": "login",
                "credential": {"username": "ana", "password": ANA_PASSWORD},
                "login_operation_id": "{{op_login}}",
            },
        ),
        (
            "beto",
            {
                "name": "beto",
                "role": "user",
                "auth_type": "bearer",
                "credential": {"token": BETO_TOKEN},
            },
        ),
        (
            "raiz",
            {
                "name": "raiz",
                "role": "admin",
                "auth_type": "bearer",
                "credential": {"token": RAIZ_TOKEN},
            },
        ),
    ]
    for who, identity in identities:
        steps.append(
            step(
                f"09 Identidad {who}",
                "POST",
                p + "/identities",
                "Credenciales falsas del laboratorio; Hindama las cifra (RN-11).",
                body=identity,
                captures={f"identity_{who}": "body.id"},
            )
        )
    steps.append(
        step(
            "10 Probar identidad ana",
            "POST",
            p + "/identities/{{identity_ana}}/test",
            "RF-29. Inicia sesión en el laboratorio con ana.",
            body={},
        )
    )
    for who, owned in RESOURCES.items():
        for resource_type, value in owned:
            steps.append(
                step(
                    f"11 Recurso {value} de {who}",
                    "POST",
                    p + "/resources",
                    "Recursos propios de cada identidad, para probar acceso a objetos ajenos.",
                    body={
                        "identity_id": "{{identity_" + who + "}}",
                        "resource_type": resource_type,
                        "value": value,
                    },
                )
            )
    steps += [
        step(
            "12 Lanzar ejecución",
            "POST",
            p + "/runs",
            "Los cuatro módulos implementados.",
            body={
                "modules": ["object_access", "function_access", "authentication", "configuration"],
                "limits": {"requests_per_second": 5, "concurrency": 2},
                "confirm_risk": True,
            },
            captures={"run_id": "body.id"},
        ),
        step(
            "13 Ver ejecución",
            "GET",
            p + "/runs/{{run_id}}",
            "Repetir hasta que `status` sea `completed`.",
        ),
        step(
            "14 Progreso en vivo (SSE)",
            "GET",
            p + "/runs/{{run_id}}/events",
            "Server-Sent Events; Postman los muestra conforme llegan.",
        ),
        step(
            "15 Matriz de resultados",
            "GET",
            p + "/runs/{{run_id}}/results?page_size=100",
            "Identidad × operación (RF-64).",
        ),
        step(
            "16 Hallazgos",
            "GET",
            p + "/findings",
            "RF-65.",
            captures={"finding_id": "body.items[0] && body.items[0].id"},
        ),
        step(
            "17 Detalle de un hallazgo",
            "GET",
            p + "/findings/{{finding_id}}",
            "Con evidencia enmascarada (RN-11).",
        ),
        step("18 Ocurrencias del hallazgo", "GET", p + "/findings/{{finding_id}}/occurrences", ""),
        step(
            "19 Volver a probar",
            "POST",
            p + "/runs/{{run_id}}/rerun",
            "CU-17, RF-71. Con el laboratorio en modo `secure`: repite la ejecución con la misma "
            "configuración y resuelve los hallazgos (RF-68). La confirmación de riesgo se pide de "
            "nuevo (RF-46). Después, repetir el paso 13 hasta `completed`.",
            body={"confirm_risk": True},
            captures={"run_id": "body.id"},
        ),
        step(
            "20 Proyecto",
            "GET",
            p,
            "Tras volver a probar con el laboratorio corregido, el proyecto queda concluido "
            "(RF-73).",
        ),
    ]
    return {
        "name": "Flujo con el laboratorio",
        "description": (
            "Ejecutar en orden. Antes: laboratorio y túnel levantados, `labUrl` en el entorno "
            "(postman/README.md)."
        ),
        "item": steps,
    }


# ------------------------------------------------------------------ output


def build(contract_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    document = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    contract = Contract(document)
    no_auth = sorted(
        path
        for path, item in document["paths"].items()
        for method, op in item.items()
        if isinstance(op, dict) and op.get("security") == []
    )
    version = document["info"]["version"]
    collection = {
        "info": {
            "name": f"Hindama API {version}",
            "description": (
                "Generada desde el contrato con `uv run python -m postman.build`. No editar a mano."
            ),
            "schema": SCHEMA,
        },
        "auth": {
            "type": "bearer",
            "bearer": [{"key": "token", "value": "{{accessToken}}", "type": "string"}],
        },
        "event": [
            {
                "listen": "prerequest",
                "script": {
                    "type": "text/javascript",
                    "exec": (AUTH_SCRIPT % {"no_auth": json.dumps(no_auth)}).splitlines(),
                },
            }
        ],
        "variable": [{"key": name, "value": ""} for name in sorted(PATH_VARIABLES)],
        "item": [lab_flow(), *contract_folders(contract)],
    }

    def variable(key: str, value: str = "", secret: bool = False) -> dict[str, Any]:
        return {
            "key": key,
            "value": value,
            "type": "secret" if secret else "default",
            "enabled": True,
        }

    environment = {
        "name": "Hindama local",
        "values": [
            variable("baseUrl", "http://localhost:8000"),
            variable("labUrl"),
            variable("cognitoRegion", "us-east-1"),
            variable("cognitoClientId"),
            variable("cognitoClientSecret", secret=True),
            variable("username"),
            variable("password", secret=True),
            variable("accessToken", secret=True),
            variable("tokenExpiresAt"),
        ],
        "_postman_variable_scope": "environment",
    }
    return collection, environment


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera la colección de Postman desde el contrato")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    args = parser.parse_args()
    collection, environment = build(args.contract)
    for name, data in (
        ("hindama.postman_collection.json", collection),
        ("local.postman_environment.json", environment),
    ):
        (HERE / name).write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"postman/{name}")  # noqa: T201 (a command-line tool)


if __name__ == "__main__":
    main()
