"""The scanner's requests as each identity (RF-29, RF-30, RF-50), against a local server, and the
choice of victims of object access (RF-35, RF-56)."""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from hindama.core.credentials import Credential
from hindama.core.identity_probe import LoginRequest
from hindama.core.safe_http import SafeHttpClient
from hindama.models.enums import AuthType, HttpMethod, IdentityRole, Policy
from hindama.scanner.context import Actor, Owned, RunContext, Target
from hindama.scanner.evidence import Masker
from hindama.scanner.limiter import RequestLimiter
from hindama.scanner.modules.object_access import ObjectAccess, _victims
from hindama.scanner.requester import SCAN_LIMITS, LoginFailedError, Requester, RequestFailedError
from tests.servers import HOST, LOOPBACK, LocalServer, ScriptedResolver, allow_loopback

PASSWORD = "clave-del-servidor-local"
STATE: dict[str, Any] = {}


async def login(request: Request) -> Response:
    body = await request.json()
    STATE["logins"] += 1
    if body.get("password") != PASSWORD:
        return JSONResponse({}, status_code=401)
    return JSONResponse({"access_token": f"token-numero-{STATE['logins']}-abcdef"})


async def private(request: Request) -> Response:
    # Only the newest token works: the first one "expires" as soon as a second login happens.
    expected = f"Bearer token-numero-{STATE['logins']}-abcdef"
    if STATE["expire_first"] and STATE["logins"] == 1:
        return JSONResponse({}, status_code=401)
    ok = request.headers.get("authorization") == expected
    return JSONResponse({"ok": ok}, status_code=200 if ok else 401)


APP = Starlette(
    routes=[Route("/login", login, methods=["POST"]), Route("/private", private)],
)


@pytest.fixture(scope="module")
def server() -> Iterator[LocalServer]:
    with LocalServer(APP) as running:
        yield running


@pytest.fixture(autouse=True)
def fresh() -> None:
    STATE.update(logins=0, expire_first=False)


def requester(base_url: str, resolver: ScriptedResolver | None = None) -> Requester:
    client = SafeHttpClient(
        HOST,
        resolver=resolver or ScriptedResolver([LOOPBACK]),
        address_policy=allow_loopback,
        limits=SCAN_LIMITS,
    )
    limiter = RequestLimiter(requests_per_second=20, concurrency=2, max_requests=50)
    return Requester(client, limiter, base_url, Masker())


def ana(base_url: str, password: str = PASSWORD) -> Actor:
    return Actor(
        id=uuid.uuid4(),
        name="ana",
        role=IdentityRole.USER,
        auth_type=AuthType.LOGIN,
        credential=Credential(username="ana", password=password),
        login=LoginRequest(f"{base_url}/login", "username", "password"),
    )


async def test_an_expired_login_token_is_renewed_once(server: LocalServer) -> None:
    base_url = f"http://{HOST}:{server.port}"
    STATE["expire_first"] = True
    sender = requester(base_url)
    actor = ana(base_url)

    exchange = await sender.send(actor, "GET", "/private")

    assert exchange.status_code == 200
    assert STATE["logins"] == 2  # RF-30
    assert sender.sent == 4  # two logins and two requests, all through the limiter
    assert "token-numero-2" not in sender.masker.text("token-numero-2-abcdef")


async def test_a_wrong_password_is_tried_once(server: LocalServer) -> None:
    base_url = f"http://{HOST}:{server.port}"
    sender = requester(base_url)
    actor = ana(base_url, password="otra")

    for _ in range(3):
        with pytest.raises(LoginFailedError):
            await sender.send(actor, "GET", "/private")

    assert STATE["logins"] == 1


async def test_an_unreachable_login_fails_the_login(server: LocalServer) -> None:
    base_url = f"http://{HOST}:1"  # nothing listens there
    with pytest.raises(LoginFailedError):
        await requester(base_url).send(ana(base_url), "GET", "/private")


async def test_a_connection_error_is_a_failed_request() -> None:
    base_url = f"http://{HOST}:1"
    with pytest.raises(RequestFailedError):
        await requester(base_url).send(anonymous(), "GET", "/private")


async def test_a_private_address_is_never_reached(server: LocalServer) -> None:
    base_url = f"http://{HOST}:{server.port}"
    with pytest.raises(RequestFailedError, match="address_not_allowed"):  # RF-50
        await requester(base_url, ScriptedResolver(["10.0.0.7"])).send(
            anonymous(), "GET", "/private"
        )


def anonymous() -> Actor:
    return Actor(uuid.uuid4(), "anónima", IdentityRole.OTHER, AuthType.NONE, None)


# ------------------------------------------------------------------ victims (RF-35, RF-56)


def bearer(name: str) -> Actor:
    return Actor(
        uuid.uuid4(), name, IdentityRole.USER, AuthType.BEARER, Credential(token=f"t-{name}-123456")
    )


def target(path: str, *parameters: tuple[str, str]) -> Target:
    return Target(uuid.uuid4(), HttpMethod.GET, path, Policy.OWNER_ONLY, parameters)


def test_nested_parameters_take_the_victims_own_resources() -> None:
    a, b = bearer("a"), bearer("b")
    nested = target(
        "/users/{user_id}/orders/{order_id}", ("user_id", "users"), ("order_id", "orders")
    )
    context = RunContext(
        run_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        base_url="http://x",
        host="x",
        targets=[nested],
        actors=[a, b],
        resources={
            "users": [Owned("u-a", a.id), Owned("u-b", b.id)],
            "orders": [Owned("o-b-1", b.id), Owned("o-b-2", b.id), Owned("o-a", a.id)],
        },
    )

    victims = list(_victims(nested, a, context))

    assert [v.path for v in victims] == ["/users/u-b/orders/o-b-1", "/users/u-b/orders/o-b-2"]
    assert {v.owner.name for v in victims} == {"b"}


def test_a_victim_without_the_other_resources_is_left_out() -> None:
    a, b = bearer("a"), bearer("b")
    nested = target(
        "/users/{user_id}/orders/{order_id}", ("user_id", "users"), ("order_id", "orders")
    )
    context = RunContext(
        uuid.uuid4(),
        uuid.uuid4(),
        "http://x",
        "x",
        [nested],
        [a, b],
        {"orders": [Owned("o-b-1", b.id)]},
    )

    assert list(_victims(nested, a, context)) == []


def test_at_most_three_victims_per_cell() -> None:
    a, b = bearer("a"), bearer("b")
    single = target("/orders/{id}", ("id", "orders"))
    owned = [Owned(f"o-{n}", b.id) for n in range(5)]
    context = RunContext(
        uuid.uuid4(), uuid.uuid4(), "http://x", "x", [single], [a, b], {"orders": owned}
    )

    assert len(list(_victims(single, a, context))) == 3


def test_only_operations_whose_parameters_are_all_resources_are_planned() -> None:
    a = bearer("a")
    plain = target("/orders/{id}", ("id", "orders"))
    unknown = target("/orders/{id}/lines/{line}", ("id", "orders"))  # `line` is not a resource
    public = Target(
        uuid.uuid4(), HttpMethod.GET, "/orders/{id}", Policy.PUBLIC, (("id", "orders"),)
    )
    context = RunContext(uuid.uuid4(), uuid.uuid4(), "http://x", "x", [plain, unknown, public], [a])

    assert [cell.target for cell in ObjectAccess().plan(context)] == [plain]
