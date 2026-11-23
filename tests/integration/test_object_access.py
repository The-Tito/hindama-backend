"""Object access, API1 (RF-56, RF-61, RF-62, RF-33, RF-47; ADR-014), against the lab's mini API.

Each test checks the catalog (hindama-docs/05-pruebas/catalogo-laboratorio.md, section 3.3): the
vulnerable mode yields exactly its findings, the secure mode none, and the decoy never.
"""

import json
import os
from uuid import UUID

import pytest
from fastapi import FastAPI
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.core.credentials import CredentialCipher
from hindama.models import (
    Finding,
    FindingEvent,
    FindingMetric,
    FindingOccurrence,
    Identity,
)
from hindama.scanner.execution import Scanner
from tests.integration.conftest import Analyst
from tests.lab.app import ANA_PASSWORD, ANA_TOKEN, BETO_TOKEN, RAIZ_TOKEN
from tests.lab.scanning import findings, lab_project, lab_scanner, matrix, run_lab, stored_run
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer

ORDER = "GET /orders/{order_id}"
DELETE_ORDER = "DELETE /orders/{order_id}"
INVOICE = "GET /invoices/{invoice_id}"
STATEMENT = "GET /accounts/{account_id}/statement"
SECRETS = (ANA_PASSWORD, ANA_TOKEN, BETO_TOKEN, RAIZ_TOKEN)


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, app: FastAPI) -> Scanner:
    return lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())


# ------------------------------------------------------------------ the catalog


async def test_the_vulnerable_lab_yields_the_catalog(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab)

    run = await stored_run(owner, run_id)
    assert (run.status, run.end_reason) == ("completed", "normal")
    assert run.cells_planned == run.cells_evaluated == 12  # 4 operations x 3 identities
    assert run.requests_sent == len(lab.state.seen)
    cells = await matrix(owner, project, run_id)
    assert cells == {
        (ORDER, "ana"): ("denied", "200 allowed", "fail"),  # LAB-API1-01
        (ORDER, "beto"): ("denied", "200 allowed", "fail"),  # LAB-API1-02
        (ORDER, "raiz"): ("denied", "200 allowed", "fail"),  # LAB-API1-03
        (STATEMENT, "ana"): ("denied", "200 allowed", "fail"),  # LAB-API1-04
        (STATEMENT, "beto"): ("denied", "200 allowed", "fail"),
        (STATEMENT, "raiz"): ("allowed", "200 allowed", "pass"),  # LAB-API1-05
        (INVOICE, "ana"): ("denied", "200 no_data", "pass"),  # LAB-API1-06, the decoy
        (INVOICE, "beto"): ("denied", "200 no_data", "pass"),
        (INVOICE, "raiz"): ("denied", "200 no_data", "pass"),
        (DELETE_ORDER, "ana"): ("denied", "method_not_safe", "skipped"),  # LAB-API1-07
        (DELETE_ORDER, "beto"): ("denied", "method_not_safe", "skipped"),
        (DELETE_ORDER, "raiz"): ("denied", "method_not_safe", "skipped"),
    }
    assert not [seen for seen in lab.state.seen if seen[0] not in ("GET", "POST")]  # RN-06
    found = await findings(owner, project)
    assert set(found) == {
        (ORDER, "ana"),
        (ORDER, "beto"),
        (ORDER, "raiz"),
        (STATEMENT, "ana"),
        (STATEMENT, "beto"),
    }
    first = found[(ORDER, "ana")]
    assert (first.status, first.severity, first.owasp_category, first.cwe) == (
        "new",
        "high",
        "API1:2023",
        "CWE-639",
    )
    assert first.finding_type == "object_access.unauthorized_read"
    body = (await ana.request("GET", f"/projects/{project.id}/runs/{run_id}")).json()
    assert body["progress"]["percent"] == 100
    assert body["progress"]["findings_by_severity"]["high"] == 5  # RF-51


async def test_the_evidence_reproduces_without_secrets(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab)

    async with AsyncSession(owner) as db:
        occurrences = list(
            await db.scalars(select(FindingOccurrence).where(FindingOccurrence.run_id == run_id))
        )
    assert len(occurrences) == 5
    stored = json.dumps([o.evidence for o in occurrences]) + repr(
        [o.explanation for o in occurrences]
    )
    for secret in SECRETS:  # RN-11: not even the login's token
        assert secret not in stored
    raiz = next(o for o in occurrences if "«raiz» obtuvo" in o.explanation)  # only GET /orders/{id}
    evidence = raiz.evidence
    assert evidence["request"]["method"] == "GET"
    assert evidence["request"]["headers"]["authorization"] == "****" + RAIZ_TOKEN[-4:]
    assert evidence["response"]["status_code"] == 200
    assert evidence["response"]["body_truncated"] is False
    assert evidence["resource"]["owner"] in ("ana", "beto")
    assert evidence["resource"]["value"] in evidence["response"]["body"]


async def test_the_secure_lab_yields_nothing(
    ana: Analyst,
    secure_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = secure_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab)

    cells = await matrix(owner, project, run_id)
    assert cells[(ORDER, "ana")] == ("denied", "404 denied", "pass")
    assert cells[(ORDER, "raiz")] == ("denied", "404 denied", "pass")
    assert cells[(STATEMENT, "beto")] == ("denied", "403 denied", "pass")
    assert cells[(STATEMENT, "raiz")] == ("allowed", "200 allowed", "pass")
    assert {verdict for _, _, verdict in cells.values()} == {"pass", "skipped"}
    assert await findings(owner, project) == {}


# ------------------------------------------------------------------ across runs (ADR-014)


async def test_a_finding_found_again_persists_and_a_resolved_one_regresses(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    first_run = await run_lab(scanner, project, lab)
    resolved = (await findings(owner, project))[(STATEMENT, "beto")]
    async with AsyncSession(owner) as db, db.begin():
        await db.execute(
            update(Finding)
            .where(Finding.id == resolved.id)
            .values(
                status="resolved",
                resolution_reason="not_detected",
                resolved_at=resolved.detected_at,
            )
        )

    second_run = await run_lab(scanner, project, lab)

    found = await findings(owner, project)
    assert len(found) == 5  # the same fingerprints: no duplicates
    assert found[(ORDER, "ana")].status == "persistent"
    assert found[(ORDER, "ana")].first_run_id == first_run
    assert found[(ORDER, "ana")].last_run_id == second_run
    regressed = found[(STATEMENT, "beto")]
    assert (regressed.status, regressed.resolution_reason) == ("regression", None)
    async with AsyncSession(owner) as db:
        metric = await db.get(FindingMetric, regressed.metric_id)
        events = list(
            await db.scalars(
                select(FindingEvent.reason, FindingEvent.from_status, FindingEvent.to_status)
                .where(FindingEvent.finding_id == regressed.id)
                .order_by(FindingEvent.id)
            )
        )
    assert metric is not None
    assert metric.regressions == 1
    assert metric.week.weekday() == 0  # a Monday (RF-89)
    assert events == ["detected", "regression"]


async def test_an_accepted_risk_stays_accepted(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    await run_lab(scanner, project, lab)
    accepted = (await findings(owner, project))[(ORDER, "raiz")]
    async with AsyncSession(owner) as db, db.begin():
        await db.execute(
            update(Finding)
            .where(Finding.id == accepted.id)
            .values(
                status="accepted_risk",
                dismissal_reason="accepted_risk",
                justification="El administrador puede leer pedidos por diseño.",
            )
        )

    run_id = await run_lab(scanner, project, lab)

    assert (await findings(owner, project))[(ORDER, "raiz")].status == "accepted_risk"
    async with AsyncSession(owner) as db:
        occurrence = await db.get(FindingOccurrence, (accepted.id, run_id))
    assert occurrence is not None  # detected again all the same


# ------------------------------------------------------------------ identities and limits


async def test_a_failed_login_skips_the_identity(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab, ana_password="otra-clave-que-no-sirve")

    run_id = await run_lab(scanner, project, lab)

    cells = await matrix(owner, project, run_id)
    assert cells[(ORDER, "ana")] == ("denied", "login_failed", "skipped")
    # beto can only be tested against ana's resources, and ana cannot show them (no control)
    assert cells[(ORDER, "beto")] == ("denied", "baseline_failed", "skipped")
    assert cells[(ORDER, "raiz")] == ("denied", "200 allowed", "fail")  # beto's order
    logins = [seen for seen in lab.state.seen if seen[1] == "/auth/login"]
    assert len(logins) == 1  # tried once per run, not once per request


async def test_an_expired_token_marks_the_identity(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab, beto_token="tok-beto-que-ya-vencio-0000")

    run_id = await run_lab(scanner, project, lab)

    async with AsyncSession(owner) as db:
        beto = await db.get(Identity, UUID(project.identities["beto"]))
    assert beto is not None
    assert beto.status == "expired_credential"  # RF-33
    cells = await matrix(owner, project, run_id)
    assert cells[(ORDER, "ana")] == ("denied", "baseline_failed", "skipped")
    assert (ORDER, "beto") not in await findings(owner, project)


async def test_the_request_budget_ends_the_run(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, max_requests=4, concurrency=1)

    run = await stored_run(owner, run_id)
    assert (run.status, run.end_reason) == ("completed", "limit_reached")  # RF-47, CU-12 E5
    assert run.requests_sent == len(lab.state.seen) == 4
    assert run.cells_evaluated < run.cells_planned


async def test_a_credential_that_cannot_be_decrypted_leaves_its_identity_out(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner_engine: AsyncEngine,
    owner: AsyncEngine,
) -> None:
    """A lost or rotated-out key (ADR-007): the identity is not tested, the run goes on."""
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    other_key = CredentialCipher({1: os.urandom(32)}, 1)
    scanner = lab_scanner(scanner_engine, other_key, ScriptedChecker())

    run_id = await run_lab(scanner, project, lab)

    run = await stored_run(owner, run_id)
    assert (run.status, run.end_reason) == ("completed", "normal")
    assert run.cells_planned == 0  # no authenticated identity left: nothing to test
    assert lab.state.seen == []
