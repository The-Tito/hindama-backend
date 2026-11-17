"""The mini API of the lab, in `secure` and `vulnerable` mode (catalogo-laboratorio.md, section 2).

Each failure of the catalog exists only in the vulnerable mode; the decoys exist in both. Its own
OpenAPI document is the contract the tests import, as an analyst would.
"""

from enum import StrEnum
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

ANA_PASSWORD = "clave-de-ana-del-laboratorio"
BETO_TOKEN = "tok-beto-laboratorio-7c1e"
RAIZ_TOKEN = "tok-raiz-laboratorio-42aa"
ANA_TOKEN = "tok-ana-emitido-por-login-91b3"
ADMIN = "raiz"

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


class Mode(StrEnum):
    SECURE = "secure"
    VULNERABLE = "vulnerable"


class LoginBody(BaseModel):
    username: str
    password: str


def build_lab(mode: Mode) -> FastAPI:
    app = FastAPI(title="Mini API del laboratorio", version="1.0")
    app.state.seen = []  # (method, path, user): what Hindama sent, for the tests
    tokens = {BETO_TOKEN: "beto", RAIZ_TOKEN: ADMIN}
    bearer = HTTPBearer(auto_error=False)

    @app.middleware("http")
    async def record(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        app.state.seen.append(
            (request.method, request.url.path, request.state.__dict__.get("user"))
        )
        return response

    def user(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> str:
        name = None if credentials is None else tokens.get(credentials.credentials)
        if name is None:
            raise HTTPException(status_code=401, detail="unauthenticated")
        request.state.user = name
        return name

    User = Annotated[str, Depends(user)]

    def own(record: dict[str, object] | None, name: str) -> dict[str, object]:
        if record is None or (mode == Mode.SECURE and record["owner"] != name):
            raise HTTPException(status_code=404, detail="not found")
        return record

    @app.post("/auth/login")
    async def login(body: LoginBody) -> dict[str, str]:
        if body.username != "ana" or body.password != ANA_PASSWORD:
            raise HTTPException(status_code=401, detail="bad credentials")
        tokens[ANA_TOKEN] = "ana"
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
    async def get_invoice(invoice_id: str, name: User) -> JSONResponse:
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
        if mode == Mode.SECURE and name not in (account["owner"], ADMIN):
            raise HTTPException(status_code=403, detail="forbidden")
        return account

    return app
