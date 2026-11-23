"""Property access, API3 (RF-58, RN-05, RN-06), against the lab's mini API.

Catalog: hindama-docs/05-pruebas/catalogo-laboratorio.md, section 10.3. Besides the findings, every
run must leave the lab's wish list empty and its `created_resources` deleted (LAB-API3-03).
"""

import json
from uuid import UUID

import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import CreatedResource, FindingOccurrence
from hindama.scanner.execution import Scanner
from tests.integration.conftest import Analyst
from tests.lab.app import ANA_PASSWORD, ANA_TOKEN
from tests.lab.scanning import lab_project, lab_scanner, matrix, run_lab, typed_findings
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer

MODULES = ("property_access",)
PROFILE = "GET /profile"
WISHLIST = "POST /wishlist"


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, app: FastAPI) -> Scanner:
    return lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())


async def created(owner: AsyncEngine, run_id: UUID) -> list[CreatedResource]:
    async with AsyncSession(owner) as db:
        return list(
            await db.scalars(select(CreatedResource).where(CreatedResource.run_id == run_id))
        )


async def test_the_vulnerable_lab_yields_the_catalog(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES)

    assert await matrix(owner, project, run_id, "property_access") == {
        (PROFILE, "ana"): ("declared_only", "undeclared_fields", "fail"),  # LAB-API3-01
        (WISHLIST, "ana"): ("rejected", "accepted", "fail"),  # LAB-API3-02
    }  # LAB-API3-04/05: no other cell
    found = await typed_findings(owner, project, "property_access")
    assert set(found) == {
        (PROFILE, "ana", "property_access.undeclared_fields"),
        (WISHLIST, "ana", "property_access.mass_assignment"),
    }
    assert {kind: f.severity for (_, _, kind), f in found.items()} == {
        "property_access.undeclared_fields": "medium",
        "property_access.mass_assignment": "high",
    }
    assert {(f.owasp_category) for f in found.values()} == {"API3:2023"}
    # LAB-API3-03: created, then deleted by Hindama itself (RN-06).
    assert lab.state.wishlist == {}
    rows = await created(owner, run_id)
    assert [(r.status, r.location, r.attempts) for r in rows] == [
        ("deleted", f"/wishlist/wish-{lab.state.created}", 1)
    ]
    order = [(m, p) for m, p, _ in lab.state.seen if p.startswith("/wishlist")]
    assert order == [("POST", "/wishlist"), ("DELETE", f"/wishlist/wish-{lab.state.created}")]


async def test_the_evidence_shows_what_was_sent_and_accepted(
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
    evidence = {o.evidence["request"]["method"]: o.evidence for o in occurrences}
    assert evidence["GET"]["undeclared"] == ["password_hash", "role"]
    mass = evidence["POST"]
    sent = json.loads(mass["request"]["body"])
    assert sent["product"] == "hindama"  # the required field, with a harmless value
    assert sent["owner"] == "hindama-asignado" and sent["role"] == "admin"
    assert sent["is_admin"] is True
    assert "id" not in sent  # never the identifier
    assert "owner" in mass["accepted_fields"] and "role" in mass["accepted_fields"]
    assert mass["created_resource"] == "deleted"
    stored = str([o.evidence for o in occurrences])
    for secret in (ANA_PASSWORD, ANA_TOKEN):  # RN-11
        assert secret not in stored


async def test_the_secure_lab_yields_nothing_and_still_cleans_up(
    ana: Analyst,
    secure_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = secure_lab
    project = await lab_project(ana, server, lab)

    run_id = await run_lab(scanner, project, lab, MODULES)

    assert await matrix(owner, project, run_id, "property_access") == {
        (PROFILE, "ana"): ("declared_only", "declared_only", "pass"),
        (WISHLIST, "ana"): ("rejected", "rejected", "pass"),
    }
    assert await typed_findings(owner, project, "property_access") == {}
    assert lab.state.wishlist == {}
    assert [r.status for r in await created(owner, run_id)] == ["deleted"]


async def test_a_run_without_budget_to_delete_creates_nothing(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)

    # 3 requests in all: never enough for one creation and its 3 deletion attempts.
    run_id = await run_lab(scanner, project, lab, MODULES, max_requests=3)

    cells = await matrix(owner, project, run_id, "property_access")
    assert cells[(WISHLIST, "ana")] == ("rejected", "budget_reserved", "skipped")
    assert await created(owner, run_id) == []
    assert ("POST", "/wishlist") not in {(m, p) for m, p, _ in lab.state.seen}
