"""Function access, API5 (RF-57, RF-61, RF-62), against the lab's mini API.

Catalog: hindama-docs/05-pruebas/catalogo-laboratorio.md, section 5.3.
"""

import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.scanner.execution import Scanner
from tests.integration.conftest import Analyst
from tests.lab.scanning import findings, lab_project, lab_scanner, matrix, run_lab
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer

USERS = "GET /admin/users"
AUDIT = "GET /admin/audit"
DELETE_USER = "DELETE /admin/users/{user_id}"
MODULES = ("function_access",)


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

    assert await matrix(owner, project, run_id) == {
        (USERS, "ana"): ("denied", "200 allowed", "fail"),  # LAB-API5-01
        (USERS, "beto"): ("denied", "200 allowed", "fail"),
        (AUDIT, "ana"): ("denied", "200 no_data", "pass"),  # LAB-API5-02, the decoy
        (AUDIT, "beto"): ("denied", "200 no_data", "pass"),
        (DELETE_USER, "ana"): ("denied", "method_not_safe", "skipped"),  # LAB-API5-03
        (DELETE_USER, "beto"): ("denied", "method_not_safe", "skipped"),
    }  # LAB-API5-04: no cell for raiz nor the anonymous identity
    found = await findings(owner, project, "function_access")
    assert set(found) == {(USERS, "ana"), (USERS, "beto")}
    finding = found[(USERS, "beto")]
    assert (finding.finding_type, finding.severity, finding.owasp_category, finding.cwe) == (
        "function_access.unauthorized_call",
        "high",
        "API5:2023",
        "CWE-285",
    )
    assert not [seen for seen in lab.state.seen if seen[0] == "DELETE"]  # RN-06


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
    assert cells[(USERS, "ana")] == ("denied", "403 denied", "pass")
    assert cells[(USERS, "beto")] == ("denied", "403 denied", "pass")
    assert await findings(owner, project, "function_access") == {}
