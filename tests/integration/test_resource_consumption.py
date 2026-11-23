"""Resource consumption, API4 (RF-59, RN-05, RN-06), against the lab's mini API.

Catalog: hindama-docs/05-pruebas/catalogo-laboratorio.md, section 8.3.
"""

from uuid import UUID

import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import FindingOccurrence, Result
from hindama.scanner.execution import Scanner
from tests.integration.conftest import Analyst
from tests.lab.app import ANA_PASSWORD, ANA_TOKEN
from tests.lab.scanning import lab_project, lab_scanner, run_lab, stored_run, typed_findings
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer

MODULES = ("resource_consumption",)
FAST = {"requests_per_second": 20}  # the burst at the fastest pace the run allows (RF-47)


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, app: FastAPI) -> Scanner:
    return lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())


async def the_cell(owner: AsyncEngine, run_id: UUID) -> Result:
    async with AsyncSession(owner) as db:
        rows = list(await db.scalars(select(Result).where(Result.run_id == run_id)))
    assert len(rows) == 1  # one cell for the whole API
    return rows[0]


def sent(lab: FastAPI, method: str, path: str) -> int:
    return sum(1 for m, p, _ in lab.state.seen if (m, p) == (method, path))


async def test_the_vulnerable_lab_yields_the_catalog(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES, **FAST)

    cell = await the_cell(owner, run_id)
    assert cell.operation_id is None
    assert project.identity(cell.identity_id) == "ana"  # the first authenticated identity
    assert (cell.expected, cell.observed, cell.verdict) == (
        "limited",
        "no_rate_limit, no_body_limit",
        "fail",
    )
    found = await typed_findings(owner, project, "resource_consumption")
    assert set(found) == {
        ("—", "ana", "resource_consumption.no_rate_limit"),  # LAB-API4-01
        ("—", "ana", "resource_consumption.no_body_limit"),  # LAB-API4-02
    }
    assert {f.severity for f in found.values()} == {"medium"}
    assert {f.owasp_category for f in found.values()} == {"API4:2023"}
    assert sent(lab, "GET", "/catalog") == 40
    assert sent(lab, "POST", "/tickets") == 3  # 64 KB, 1 MB and 8 MB
    run = await stored_run(owner, run_id)
    assert run.requests_sent <= 43 + 1  # plus ana's login


async def test_the_body_evidence_keeps_only_its_start(
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
    body = next(o.evidence for o in occurrences if "request_body_bytes" in o.evidence)
    assert body["request_body_bytes"] == 8 * 1024 * 1024
    assert body["operation"] == "POST /tickets"
    assert body["request"]["body"].startswith('["aaa')
    assert len(body["request"]["body"]) <= 1024  # never the 8 MB
    assert body["response"]["status_code"] == 422  # read whole, then rejected: nothing created
    burst = next(o.evidence for o in occurrences if "requests" in o.evidence)
    assert (burst["requests"], burst["operation"]) == (40, "GET /catalog")
    assert "body" not in burst["request"]  # a GET carries none
    stored = str([o.evidence for o in occurrences])
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

    cell = await the_cell(owner, run_id)
    assert (cell.expected, cell.observed, cell.verdict) == ("limited", "limited", "pass")
    assert await typed_findings(owner, project, "resource_consumption") == {}
    assert sent(lab, "GET", "/catalog") == 21  # it stops at the first 429
    assert sent(lab, "POST", "/tickets") <= 3  # 413 at 1 MB (or a cut connection)


async def test_it_needs_the_risk_confirmation(
    ana: Analyst, vulnerable_lab: tuple[LocalServer, FastAPI]
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    response = await ana.request(
        "POST", f"/projects/{project.id}/runs", json={"modules": list(MODULES)}
    )

    assert response.status_code == 422
    assert response.json()["code"] == "run.risk_not_confirmed"  # RN-05: high risk
