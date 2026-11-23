"""SQL injection without a network: its payloads stay read only (RF-60, RN-06)."""

import uuid

from hindama.models.enums import AuthType, HttpMethod, IdentityRole, Policy
from hindama.scanner.context import Actor, Owned, Parameter, RunContext, Target
from hindama.scanner.modules.sql_injection import (
    SQL_ERRORS,
    SqlInjection,
    base_values,
    payloads,
    request_path,
)

ANA = Actor(uuid.uuid4(), "ana", IdentityRole.USER, AuthType.BEARER, None)
TEXT = Parameter("name", "query", False, "string")
NUMBER = Parameter("id", "path", True, "integer")


def target(method: HttpMethod, path: str, *parameters: Parameter, resources: tuple = ()) -> Target:
    return Target(uuid.uuid4(), method, path, Policy.AUTHENTICATED, resources, parameters)


def test_the_payloads_never_write_wait_or_stack() -> None:
    for parameter, base in ((TEXT, "hindama"), (NUMBER, "1")):
        for payload in payloads(parameter, base):
            assert payload.startswith(base)
            for word in (";", "UPDATE", "DELETE", "DROP", "INSERT", "SLEEP", "WAITFOR", "--"):
                assert word not in payload.upper()
    assert payloads(NUMBER, "1") == ("1'", "1 OR 1=1", "1 AND 1=2")  # no quotes for a number


def test_base_values_use_the_identitys_own_resource() -> None:
    order = Parameter("order_id", "path", True, "string")
    tracked = target(
        HttpMethod.GET, "/orders/{order_id}", order, TEXT, resources=(("order_id", "orders"),)
    )
    context = RunContext(
        uuid.uuid4(),
        uuid.uuid4(),
        "https://api.x",
        "api.x",
        [tracked],
        [ANA],
        {"orders": [Owned("ord-otro", uuid.uuid4()), Owned("ord-mio", ANA.id)]},
    )

    values = base_values(tracked, ANA, context)

    assert values == {"order_id": "ord-mio", "name": "hindama"}
    assert request_path(tracked, {**values, "name": "a' OR '1'='1"}) == (
        "/orders/ord-mio?name=a%27+OR+%271%27%3D%271"
    )


def test_only_get_operations_with_path_or_query_parameters_get_a_cell() -> None:
    header = Parameter("X-Trace", "header", False, "string")
    targets = [
        target(HttpMethod.GET, "/products", TEXT),
        target(HttpMethod.POST, "/products", TEXT),  # never written to (RN-06)
        target(HttpMethod.GET, "/health"),
        target(HttpMethod.GET, "/ping", header),
    ]
    context = RunContext(uuid.uuid4(), uuid.uuid4(), "https://api.x", "api.x", targets, [ANA])

    cells = SqlInjection().plan(context)

    assert [cell.target for cell in cells] == [targets[0]]


def test_database_errors_are_recognised() -> None:
    for text in (
        'sqlite3.OperationalError: unrecognized token: "\'"',
        'ERROR: syntax error at or near "\'" SQLSTATE[42601]',
        "You have an error in your SQL syntax; check the manual",
        "ORA-01756: quoted string not properly terminated",
    ):
        assert SQL_ERRORS.search(text)
    assert not SQL_ERRORS.search('{"detail": "Not Found"}')
