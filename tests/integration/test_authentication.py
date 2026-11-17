"""Authentication, API2 (RF-54, RF-61, RF-62, RN-11), against the lab's mini API.

Catalog: hindama-docs/05-pruebas/catalogo-laboratorio.md, section 6.3. The last test runs the three
modules together, as an analyst would launch a full run (RF-44).
"""

import json

import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import FindingOccurrence
from hindama.scanner.execution import Scanner
from tests.integration.conftest import Analyst
from tests.lab.app import ANA_PASSWORD, ANA_TOKEN, BETO_TOKEN, RAIZ_TOKEN
from tests.lab.scanning import lab_project, lab_scanner, matrix, run_lab, stored_run, typed_findings
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer

ORDERS = "GET /orders"
ORDER = "GET /orders/{order_id}"
DELETE_ORDER = "DELETE /orders/{order_id}"
INVOICE = "GET /invoices/{invoice_id}"
STATEMENT = "GET /accounts/{account_id}/statement"
REPORTS = "GET /reports"
USERS = "GET /admin/users"
AUDIT = "GET /admin/audit"
DELETE_USER = "DELETE /admin/users/{user_id}"
MODULES = ("authentication",)
ANONYMOUS = "anónima"
DENIED_401 = ("denied", "401 denied", "pass")
UNSAFE = ("denied", "method_not_safe", "skipped")


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, app: FastAPI) -> Scanner:
    return lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())


async def test_the_vulnerable_lab_yields_the_catalog(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES)

    forged = ("denied", "200 allowed", "fail")
    assert await matrix(owner, project, run_id) == {
        (REPORTS, ANONYMOUS): ("denied", "200 allowed", "fail"),  # LAB-API2-01
        (ORDERS, ANONYMOUS): DENIED_401,  # LAB-API2-02
        (ORDER, ANONYMOUS): DENIED_401,
        (INVOICE, ANONYMOUS): DENIED_401,
        (STATEMENT, ANONYMOUS): DENIED_401,
        (USERS, ANONYMOUS): DENIED_401,
        (AUDIT, ANONYMOUS): DENIED_401,
        (ORDERS, "ana"): forged,  # LAB-API2-03
        (ORDER, "ana"): forged,
        (INVOICE, "ana"): forged,
        (STATEMENT, "ana"): forged,
        (REPORTS, "ana"): ("denied", "no_auth_required", "skipped"),  # LAB-API2-04
        (DELETE_ORDER, ANONYMOUS): UNSAFE,  # LAB-API2-05
        (DELETE_USER, ANONYMOUS): UNSAFE,
        (DELETE_ORDER, "ana"): UNSAFE,
    }  # LAB-API2-06 and 07: no cell for beto and raiz, nor for ana on the admin operations
    found = await typed_findings(owner, project, "authentication")
    assert set(found) == {
        (REPORTS, ANONYMOUS, "authentication.no_credentials"),
        *(
            (operation, "ana", f"authentication.{kind}")
            for operation in (ORDERS, ORDER, INVOICE, STATEMENT)
            for kind in ("tampered_signature", "alg_none")
        ),
    }
    bare = found[(REPORTS, ANONYMOUS, "authentication.no_credentials")]
    assert (bare.severity, bare.owasp_category, bare.cwe) == ("high", "API2:2023", "CWE-306")
    none = found[(ORDER, "ana", "authentication.alg_none")]
    assert (none.severity, none.cwe) == ("critical", "CWE-347")
    assert not [seen for seen in lab.state.seen if seen[0] == "DELETE"]  # RN-06


async def test_forged_tokens_never_reach_the_evidence(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES)

    async with AsyncSession(owner) as db:
        occurrences = list(
            await db.scalars(select(FindingOccurrence).where(FindingOccurrence.run_id == run_id))
        )
    assert len(occurrences) == 9
    stored = json.dumps([o.evidence for o in occurrences])
    claims = ANA_TOKEN.split(".")[1]
    for secret in (ANA_PASSWORD, ANA_TOKEN, BETO_TOKEN, RAIZ_TOKEN, claims):  # RN-11
        assert secret not in stored
    headers = [o.evidence["request"]["headers"] for o in occurrences]
    assert all(h.get("authorization", "****").startswith("****") for h in headers)


async def test_the_secure_lab_yields_nothing(
    ana: Analyst,
    secure_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = secure_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES)

    cells = await matrix(owner, project, run_id)
    assert cells[(REPORTS, ANONYMOUS)] == DENIED_401  # also with empty credentials
    assert cells[(ORDER, "ana")] == DENIED_401  # neither forged token is accepted
    assert cells[(REPORTS, "ana")] == DENIED_401
    assert {verdict for _, _, verdict in cells.values()} == {"pass", "skipped"}
    assert await typed_findings(owner, project, "authentication") == {}
    empty = [seen for seen in lab.state.seen if seen[1] == "/reports"]
    assert len(empty) >= 3  # the control, without credentials, and with them empty


async def test_a_full_run_with_the_three_modules(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(
        scanner, project, lab, ("object_access", "function_access", "authentication")
    )

    run = await stored_run(owner, run_id)
    assert (run.status, run.end_reason) == ("completed", "normal")
    assert run.cells_planned == run.cells_evaluated == 15 + 12 + 6
    assert run.requests_sent == len(lab.state.seen)
    body = (await ana.request("GET", f"/projects/{project.id}/runs/{run_id}")).json()
    severities = body["progress"]["findings_by_severity"]
    assert (severities["critical"], severities["high"], severities["total"]) == (8, 8, 16)


async def test_a_failed_login_moves_the_control_to_another_identity(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab, ana_password="otra-clave-que-no-sirve")

    run_id = await run_lab(scanner, project, lab, MODULES)

    cells = await matrix(owner, project, run_id)
    assert cells[(ORDER, "ana")] == ("denied", "login_failed", "skipped")
    assert cells[(ORDER, ANONYMOUS)] == DENIED_401  # beto's order served as the control
    assert cells[(REPORTS, ANONYMOUS)] == ("denied", "200 allowed", "fail")
    found = await typed_findings(owner, project, "authentication")
    assert set(found) == {(REPORTS, ANONYMOUS, "authentication.no_credentials")}
