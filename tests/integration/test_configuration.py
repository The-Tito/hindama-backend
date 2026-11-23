"""Configuration, API8 (RF-55, RF-61, RF-62), against the lab's mini API.

Catalog: hindama-docs/05-pruebas/catalogo-laboratorio.md, section 7.3.
"""

import json
from uuid import UUID

import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import FindingOccurrence, Result
from hindama.scanner.execution import Scanner
from tests.integration.conftest import Analyst
from tests.lab.app import ANA_PASSWORD, ANA_TOKEN, BETO_TOKEN, RAIZ_TOKEN
from tests.lab.scanning import lab_project, lab_scanner, run_lab, stored_run, typed_findings
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer

MODULES = ("configuration",)
WHOLE_API = "—"


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, app: FastAPI) -> Scanner:
    return lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())


async def the_cell(owner: AsyncEngine, run_id: UUID) -> Result:
    async with AsyncSession(owner) as db:
        rows = list(await db.scalars(select(Result).where(Result.run_id == run_id)))
    assert len(rows) == 1  # one cell for the whole API
    return rows[0]


async def test_the_vulnerable_lab_yields_the_catalog(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES)

    cell = await the_cell(owner, run_id)
    assert cell.operation_id is None
    assert project.identity(cell.identity_id) == "anónima"
    assert (cell.expected, cell.verdict) == ("hardened", "fail")
    assert cell.observed == (
        "missing_header.nosniff, missing_header.frame_options, "
        "cors.any_origin_with_credentials, version_disclosure, error_details"
    )
    found = await typed_findings(owner, project, "configuration")
    assert {kind for _, _, kind in found} == {
        "configuration.missing_header.nosniff",  # LAB-API8-01
        "configuration.missing_header.frame_options",  # LAB-API8-02
        "configuration.cors.any_origin_with_credentials",  # LAB-API8-04
        "configuration.error_details",  # LAB-API8-05
        "configuration.version_disclosure",  # LAB-API8-06
    }  # LAB-API8-03: no HSTS finding over HTTP
    assert {(operation, identity) for operation, identity, _ in found} == {(WHOLE_API, "anónima")}
    severities = {kind: f.severity for (_, _, kind), f in found.items()}
    assert severities["configuration.cors.any_origin_with_credentials"] == "medium"
    assert severities["configuration.version_disclosure"] == "info"
    run = await stored_run(owner, run_id)
    assert run.requests_sent == len(lab.state.seen) <= 6 + 1  # plus ana's login
    assert {method for method, *_ in lab.state.seen} <= {"GET", "POST"}  # the POST is the login


async def test_the_error_evidence_shows_the_trace_but_no_secret(
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
    stored = json.dumps([o.evidence for o in occurrences])
    for secret in (ANA_PASSWORD, ANA_TOKEN, BETO_TOKEN, RAIZ_TOKEN):  # RN-11
        assert secret not in stored
    error = next(o for o in occurrences if "Traceback" in o.evidence["response"]["body"])
    assert error.evidence["response"]["status_code"] == 500
    assert "/invoices/hindama" in error.evidence["request"]["url"]
    assert error.evidence["request"]["headers"]["authorization"].startswith("****")


async def test_the_secure_lab_yields_nothing(
    ana: Analyst,
    secure_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = secure_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES)

    cell = await the_cell(owner, run_id)
    assert (cell.expected, cell.observed, cell.verdict) == ("hardened", "hardened", "pass")
    assert await typed_findings(owner, project, "configuration") == {}
    assert ("GET", "/hindama-ruta-inexistente", None) in lab.state.seen  # LAB-API8-07, the decoy
