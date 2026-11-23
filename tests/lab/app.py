"""The mini API of the lab, in `secure` and `vulnerable` mode (catalogo-laboratorio.md, section 2).

Each failure of the catalog exists only in the vulnerable mode; the decoys exist in both. Its own
OpenAPI document is the contract the tests import, as an analyst would.

`ana` logs in and gets a JWT (HS256). The vulnerable mode reads it without checking the signature
and accepts `alg: none`; the secure mode verifies it and requires HS256.

Configuration (section 2.2): the vulnerable mode sends no security headers, reflects any `Origin`
with credentials, announces its version and answers a malformed invoice id with its traceback.
"""

import base64
import binascii
import hashlib
import hmac
import json
import traceback
from enum import StrEnum
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

ANA_PASSWORD = "clave-de-ana-del-laboratorio"
BETO_TOKEN = "tok-beto-laboratorio-7c1e"
RAIZ_TOKEN = "tok-raiz-laboratorio-42aa"
JWT_KEY = b"llave-del-laboratorio-que-nadie-mas-conoce"
ADMIN = "raiz"
USERS = {"ana": "user", "beto": "user", ADMIN: "admin"}

ORDERS = {
    "ord-ana-1": {"id": "ord-ana-1", "owner": "ana", "total": 120},
    "ord-beto-1": {"id": "ord-beto-1", "owner": "beto", "total": 75},
}
INVOICES = {
    "inv-ana-1": {"id": "inv-ana-1", "owner": "ana", "amount": 300},
    "inv-beto-1": {"id": "inv-beto-1", "owner": "beto", "amount": 90},
}
ACCOUNTS = {
    "acc-ana": {"id": "acc-ana", "owner": "ana", "balance": 5000},
    "acc-beto": {"id": "acc-beto", "owner": "beto", "balance": 1200},
}
REPORTS = [{"id": "rep-1", "title": "Ventas de noviembre"}]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def issue_jwt(subject: str) -> str:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = _b64(json.dumps({"sub": subject, "exp": 4_102_444_800}).encode())  # year 2100
    signature = hmac.new(JWT_KEY, f"{head}.{claims}".encode(), hashlib.sha256).digest()
    return f"{head}.{claims}.{_b64(signature)}"


ANA_TOKEN = issue_jwt("ana")  # what the login answers: deterministic, so the tests can look for it


def read_jwt(token: str, *, verify: bool) -> str | None:
    try:
        head, claims, signature = token.split(".")
        header: dict[str, Any] = json.loads(_unb64(head))
        subject = json.loads(_unb64(claims)).get("sub")
        if verify:
            expected = hmac.new(JWT_KEY, f"{head}.{claims}".encode(), hashlib.sha256).digest()
            if header.get("alg") != "HS256" or not hmac.compare_digest(expected, _unb64(signature)):
                return None
    except (ValueError, binascii.Error, AttributeError):
        return None
    return subject if subject in USERS else None


class Mode(StrEnum):
    SECURE = "secure"
    VULNERABLE = "vulnerable"


class LoginBody(BaseModel):
    username: str
    password: str


def build_lab(mode: Mode) -> FastAPI:
    app = FastAPI(title="Mini API del laboratorio", version="1.2")
    app.state.seen = []  # (method, path, user): what Hindama sent, for the tests
    # Read on every request: a test can fix the lab between two runs (task 4.2, RF-68).
    app.state.mode = mode
    tokens = {BETO_TOKEN: "beto", RAIZ_TOKEN: ADMIN}
    bearer = HTTPBearer(auto_error=False)
    Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]

    @app.middleware("http")
    async def record(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        app.state.seen.append(
            (request.method, request.url.path, request.state.__dict__.get("user"))
        )
        if app.state.mode == Mode.SECURE:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        else:
            response.headers["X-Powered-By"] = "Python/3.12 FastAPI/0.115"  # LAB-API8-06
            origin = request.headers.get("origin")
            if origin is not None:  # LAB-API8-04: any origin, with credentials
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    def user(request: Request, credentials: Credentials) -> str:
        name = None
        if credentials is not None:
            token = credentials.credentials
            name = tokens.get(token)
            if name is None and token.count(".") == 2:
                name = read_jwt(token, verify=app.state.mode == Mode.SECURE)
        if name is None:
            raise HTTPException(status_code=401, detail="unauthenticated")
        request.state.user = name
        return name

    User = Annotated[str, Depends(user)]

    def own(record: dict[str, object] | None, name: str) -> dict[str, object]:
        if record is None or (app.state.mode == Mode.SECURE and record["owner"] != name):
            raise HTTPException(status_code=404, detail="not found")
        return record

    def admin(name: str) -> None:
        if app.state.mode == Mode.SECURE and name != ADMIN:
            raise HTTPException(status_code=403, detail="forbidden")

    @app.post("/auth/login")
    async def login(body: LoginBody) -> dict[str, str]:
        if body.username != "ana" or body.password != ANA_PASSWORD:
            raise HTTPException(status_code=401, detail="bad credentials")
        return {"access_token": ANA_TOKEN}

    @app.get("/orders")
    async def list_orders(name: User) -> list[dict[str, object]]:
        return [o for o in ORDERS.values() if o["owner"] == name]

    @app.get("/orders/{order_id}")
    async def get_order(order_id: str, name: User) -> dict[str, object]:
        return own(ORDERS.get(order_id), name)

    @app.delete("/orders/{order_id}", status_code=204)
    async def delete_order(order_id: str, name: User) -> Response:
        own(ORDERS.get(order_id), name)
        return Response(status_code=204)  # nothing is really deleted: the lab stays the same

    @app.get("/invoices/{invoice_id}")
    async def get_invoice(invoice_id: str, name: User) -> Response:
        if app.state.mode == Mode.VULNERABLE and not invoice_id.startswith("inv-"):
            try:
                int(invoice_id)  # an old numeric id, the way the legacy code parsed it
            except ValueError as error:
                # LAB-API8-05: a debug handler sends the traceback, with the server's paths.
                text = "".join(traceback.format_exception(error))
                return PlainTextResponse(text, status_code=500)
        invoice = INVOICES.get(invoice_id)
        if invoice is None or invoice["owner"] != name:
            # The decoy (LAB-API1-06): a 200 that carries an error, in both modes.
            return JSONResponse({"error": "not_found"})
        return JSONResponse(invoice)

    @app.get("/accounts/{account_id}/statement")
    async def get_statement(account_id: str, name: User) -> dict[str, object]:
        account = ACCOUNTS.get(account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="not found")
        if app.state.mode == Mode.SECURE and name not in (account["owner"], ADMIN):
            raise HTTPException(status_code=403, detail="forbidden")
        return account

    @app.get("/reports")
    async def list_reports(request: Request, credentials: Credentials) -> list[dict[str, str]]:
        if app.state.mode == Mode.SECURE:  # LAB-API2-01: the vulnerable mode forgot to check
            user(request, credentials)
        return REPORTS

    @app.get("/admin/users")
    async def list_users(name: User) -> list[dict[str, str]]:
        admin(name)  # LAB-API5-01: the vulnerable mode lets any authenticated user in
        return [{"name": n, "role": role} for n, role in USERS.items()]

    @app.get("/admin/audit")
    async def audit(name: User) -> JSONResponse:
        if name != ADMIN:
            # The decoy (LAB-API5-02): a 200 that carries an error, in both modes.
            return JSONResponse({"error": "forbidden"})
        return JSONResponse({"entries": [{"action": "login", "user": "ana"}]})

    @app.delete("/admin/users/{user_id}", status_code=204)
    async def delete_user(user_id: str, name: User) -> Response:
        admin(name)
        return Response(status_code=204)

    return app
