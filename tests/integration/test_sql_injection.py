"""SQL injection, CWE-89 (RF-60, RN-05, RN-06), against the lab's mini API.

Catalog: hindama-docs/05-pruebas/catalogo-laboratorio.md, section 9.3.
"""

import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import FindingOccurrence
from hindama.scanner.execution import Scanner
from tests.integration.conftest import Analyst
from tests.lab.app import ANA_PASSWORD, ANA_TOKEN
from tests.lab.scanning import lab_project, lab_scanner, matrix, run_lab, typed_findings
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer

MODULES = ("sql_injection",)
FAST = {"requests_per_second": 20}
SEARCH = "GET /products"
PRODUCT = "GET /products/{product_id}"
DECOYS = (
    "GET /orders/{order_id}",
    "GET /invoices/{invoice_id}",
    "GET /accounts/{account_id}/statement",
)


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

    run_id = await run_lab(scanner, project, lab, MODULES, **FAST)

    cells = await matrix(owner, project, run_id, "sql_injection")
    assert cells == {
        (SEARCH, "ana"): ("not_injectable", "error_based, boolean_based", "fail"),  # LAB-SQL-01
        (PRODUCT, "ana"): ("not_injectable", "error_based, boolean_based", "fail"),  # LAB-SQL-02
        **{(op, "ana"): ("not_injectable", "not_injectable", "pass") for op in DECOYS},  # 03
    }  # LAB-SQL-04: no other cell
    found = await typed_findings(owner, project, "sql_injection")
    assert set(found) == {
        (op, "ana", f"sql_injection.{kind}")
        for op in (SEARCH, PRODUCT)
        for kind in ("error_based", "boolean_based")
    }
    severities = {kind: f.severity for (_, _, kind), f in found.items()}
    assert severities == {
        "sql_injection.error_based": "high",
        "sql_injection.boolean_based": "critical",
    }
    assert {(f.owasp_category, f.cwe) for f in found.values()} == {("API8:2023", "CWE-89")}
    assert {method for method, *_ in lab.state.seen} <= {"GET", "POST"}  # the POST is the login


async def test_the_evidence_names_the_parameter_and_the_payload(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES, **FAST)

    async with AsyncSession(owner) as db:
        occurrences = list(
            await db.scalars(select(FindingOccurrence).where(FindingOccurrence.run_id == run_id))
        )
    evidence = [o.evidence for o in occurrences]
    search = [e for e in evidence if e["parameter"] == "name"]
    assert {e["payload"] for e in search} == {"hindama'", "hindama' OR '1' LIKE '1"}
    error = next(e for e in search if e["payload"] == "hindama'")
    assert error["response"]["status_code"] == 500
    assert "sqlite3.OperationalError" in error["response"]["body"]
    assert "name=hindama%27" in error["request"]["url"]
    stored = str(evidence)
    for secret in (ANA_PASSWORD, ANA_TOKEN):  # RN-11
        assert secret not in stored


async def test_the_secure_lab_yields_nothing(
    ana: Analyst,
    secure_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = secure_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES, **FAST)

    cells = await matrix(owner, project, run_id, "sql_injection")
    assert set(cells.values()) == {("not_injectable", "not_injectable", "pass")}
    assert len(cells) == 5
    assert await typed_findings(owner, project, "sql_injection") == {}
