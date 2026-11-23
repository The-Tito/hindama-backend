"""`/projects/{project_id}/findings` (CU-15; RF-62, RF-65, RF-66, RF-72, RN-02, RN-11).

Two kinds of tests: the scanner against the vulnerable lab, for what a real run leaves (evidence
without secrets, occurrences and history across runs); and rows written here as the scanner writes
them, for order, filters and the states a scan in the lab does not reach.
"""

import json
import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.models import Finding, FindingEvent, FindingMetric, FindingOccurrence, Run, User
from hindama.scanner.execution import Scanner
from tests.audit import audit_entries
from tests.integration.conftest import Analyst
from tests.integration.test_run_results import Matrix, new_matrix
from tests.integration.test_runs import owner_session
from tests.lab.app import ANA_PASSWORD, ANA_TOKEN, BETO_TOKEN, RAIZ_TOKEN
from tests.lab.scanning import lab_project, lab_scanner, run_lab
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer

SECRETS = (ANA_PASSWORD, ANA_TOKEN, BETO_TOKEN, RAIZ_TOKEN)
ORDER = "GET /orders/{order_id}"


def findings_url(project_id: str) -> str:
    return f"/projects/{project_id}/findings"


# ------------------------------------------------------------------ a real run (the lab)


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, app: FastAPI) -> Scanner:
    return lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())


async def test_findings_of_two_runs_of_the_lab(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    owner: AsyncEngine,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    url = findings_url(project.id)

    first_run = await run_lab(scanner, project, lab)
    after_one = (await ana.request("GET", url)).json()
    second_run = await run_lab(scanner, project, lab)
    listed = (await ana.request("GET", url)).json()

    async with await owner_session(owner) as db:
        stored = await db.scalar(
            select(func.count()).select_from(Finding).where(Finding.project_id == UUID(project.id))
        )
    assert listed["total"] == after_one["total"] == stored == 5  # catalog: LAB-API1-01 to 04
    assert {item["status"] for item in after_one["items"]} == {"new"}
    assert {item["status"] for item in listed["items"]} == {"persistent"}  # detected again
    order_ana = next(
        item
        for item in listed["items"]
        if item["operation"]["path"] == "/orders/{order_id}" and item["identity"]["name"] == "ana"
    )
    assert order_ana["first_run"]["id"] == str(first_run)
    assert order_ana["last_run"] == {"id": str(second_run), "number": 2}
    assert order_ana["detected_at"] < order_ana["last_detected_at"]
    assert {
        key: order_ana[key]
        for key in ("module", "finding_type", "title", "severity", "owasp_category", "cwe")
    } == {
        "module": "object_access",
        "finding_type": "object_access.unauthorized_read",
        "title": "Acceso a un objeto de otra identidad",
        "severity": "high",
        "owasp_category": "API1:2023",
        "cwe": "CWE-639",
    }

    detail = (await ana.request("GET", f"{url}/{order_ana['id']}")).json()
    occurrences = (await ana.request("GET", f"{url}/{order_ana['id']}/occurrences")).json()

    assert detail["recommendation"].startswith("Comprueba en el servidor")
    assert (detail["dismissal"], detail["resolution_reason"]) == (None, None)
    assert [(e["from_status"], e["to_status"], e["reason"]) for e in detail["history"]] == [
        (None, "new", "detected"),
        ("new", "persistent", "detected"),
    ]
    assert [e["run"]["number"] for e in detail["history"]] == [1, 2]
    evidence = detail["last_occurrence"]["evidence"]
    assert detail["last_occurrence"]["run"]["number"] == 2
    assert evidence["request"]["method"] == "GET"
    assert evidence["request"]["body"] is None
    assert evidence["request"]["headers"]["authorization"].startswith("****")  # RN-11
    assert evidence["response"]["status_code"] == 200
    assert evidence["response"]["body_truncated"] is False
    assert set(evidence["context"]) == {"resource"}
    assert set(evidence["context"]["resource"]) == {"type", "value", "owner"}
    assert "«ana»" in detail["last_occurrence"]["explanation"]
    assert [item["run"]["number"] for item in occurrences["items"]] == [2, 1]
    assert occurrences["total"] == 2
    assert occurrences["items"][0] == detail["last_occurrence"]

    # RN-11: no credential of the lab in anything the API answered (RF-31 keeps 4 characters).
    answered = json.dumps([listed, detail, occurrences])
    assert not [secret for secret in SECRETS if secret in answered]

    from_first_run = (await ana.request("GET", f"{url}?run_id={first_run}")).json()
    assert from_first_run["total"] == 5


# ------------------------------------------------------------------ rows written here

T0 = datetime(2026, 11, 16, 18, 0, tzinfo=UTC)


class Seeded:
    """A project with two finished runs and findings written as the scanner writes them."""

    def __init__(self, matrix: Matrix) -> None:
        self.matrix = matrix
        self.project = matrix.project
        self.runs: list[str] = [matrix.run_id]
        self.findings: dict[str, str] = {}  # label -> id

    @property
    def url(self) -> str:
        return findings_url(self.project.id)

    async def get(self, suffix: str = "", analyst: Analyst | None = None) -> Any:
        return await (analyst or self.project.analyst).request("GET", f"{self.url}{suffix}")


async def finish(owner: AsyncEngine, run_id: str) -> None:
    async with await owner_session(owner) as db, db.begin():
        run = await db.get(Run, UUID(run_id))
        assert run is not None
        run.status, run.end_reason = "completed", "normal"
        run.started_at = run.finished_at = func.now()


async def add_finding(
    owner: AsyncEngine,
    seeded: Seeded,
    label: str,
    *,
    module: str = "object_access",
    finding_type: str | None = None,  # by default its own, so fingerprints never collide
    severity: str = "high",
    operation: tuple[str, str] | None = ("GET", "/orders"),
    identity: str = "Cliente A",
    detections: list[tuple[int, int]],  # (run index, minutes after T0)
    status: str = "persistent",
    analyst_events: Sequence[tuple[str, str, str, str | None]] = (),
    **fields: Any,
) -> None:
    """A finding, an occurrence per detection and the events: detected by the runs, then the
    analyst's `(from, to, reason, justification)`."""
    matrix = seeded.matrix
    project_id = UUID(seeded.project.id)
    run_ids = [UUID(seeded.runs[index]) for index, _ in detections]
    async with await owner_session(owner) as db, db.begin():
        user_id = await db.scalar(
            select(User.id).where(User.cognito_sub == seeded.project.analyst.sub)
        )
        metric = FindingMetric(
            week=date(2026, 11, 16),
            module=module,
            owasp_category="API1:2023",
            cwe="CWE-639",
            severity=severity,
        )
        db.add(metric)
        await db.flush()
        finding = Finding(
            project_id=project_id,
            module=module,
            finding_type=finding_type or f"{module}.test_{label}",
            operation_id=None if operation is None else UUID(matrix.operations[operation]),
            identity_id=UUID(matrix.identities[identity]),
            severity=severity,
            owasp_category="API1:2023",
            cwe="CWE-639",
            title=f"Hallazgo {label}",
            recommendation="Corrígelo.",
            status=status,
            detected_at=T0 + timedelta(minutes=detections[0][1]),
            first_run_id=run_ids[0],
            last_run_id=run_ids[-1],
            metric_id=metric.id,
            **fields,
        )
        db.add(finding)
        await db.flush()
        previous: str | None = None
        for run_id, (_, minutes) in zip(run_ids, detections, strict=True):
            at = T0 + timedelta(minutes=minutes)
            db.add(
                FindingOccurrence(
                    finding_id=finding.id,
                    run_id=run_id,
                    project_id=project_id,
                    severity=severity,
                    explanation=f"Explicación de {label}.",
                    evidence={
                        "request": {"method": "GET", "url": "https://api/x", "headers": {}},
                        "response": {
                            "status_code": 200,
                            "headers": {"content-type": "text/plain"},
                            "body": "<script>alert(1)</script>",
                            "body_truncated": True,
                        },
                        "control_identity": "raiz",
                    },
                    detected_at=at,
                )
            )
            to = "new" if previous is None else "persistent"
            if previous != to:
                db.add(
                    FindingEvent(
                        project_id=project_id,
                        finding_id=finding.id,
                        from_status=previous,
                        to_status=to,
                        reason="detected",
                        run_id=run_id,
                        occurred_at=at,
                    )
                )
            previous = to
        for minutes, (from_status, to_status, reason, justification) in enumerate(
            analyst_events, start=100
        ):
            db.add(
                FindingEvent(
                    project_id=project_id,
                    finding_id=finding.id,
                    from_status=from_status,
                    to_status=to_status,
                    reason=reason,
                    user_id=user_id,
                    justification=justification,
                    occurred_at=T0 + timedelta(minutes=minutes),
                )
            )
    seeded.findings[label] = str(finding.id)


@pytest.fixture
async def seeded(ana: Analyst, owner: AsyncEngine) -> Seeded:
    matrix = await new_matrix(ana, owner)
    created = Seeded(matrix)
    await finish(owner, matrix.run_id)
    second = (await matrix.project.launch()).json()
    created.runs.append(second["id"])
    await finish(owner, second["id"])
    users = ("GET", "/users")
    # Written in no particular order; the endpoint sorts them.
    await add_finding(owner, created, "bajo", severity="low", detections=[(0, 1)], status="new")
    await add_finding(owner, created, "alto-viejo", detections=[(0, 2), (1, 30)])
    await add_finding(
        owner,
        created,
        "critico",
        severity="critical",
        operation=users,
        identity="Cliente B",
        detections=[(1, 31)],
        status="new",
    )
    await add_finding(
        owner,
        created,
        "alto-reciente",
        identity="Cliente B",
        detections=[(1, 32)],
        status="new",
    )
    await add_finding(
        owner,
        created,
        "cors",
        module="configuration",
        finding_type="configuration.cors_wildcard",
        severity="medium",
        operation=None,
        identity="Anónimo",
        detections=[(0, 3)],
        status="resolved",
        resolution_reason="not_detected",
        resolved_at=T0 + timedelta(minutes=40),
    )
    await add_finding(
        owner,
        created,
        "aceptado",
        severity="info",
        operation=users,
        detections=[(0, 4)],
        status="accepted_risk",
        dismissal_reason="false_positive",
        justification="Es un dato público.",
        analyst_events=[("new", "accepted_risk", "false_positive", "Es un dato público.")],
    )
    await add_finding(
        owner,
        created,
        "borrada",
        severity="low",
        operation=users,
        identity="Cliente C",
        detections=[(0, 5)],
        status="resolved",
        resolution_reason="identity_deleted",
        resolved_at=T0 + timedelta(minutes=50),
        analyst_events=[("new", "resolved", "identity_deleted", None)],
    )
    return created


def labels(seeded: Seeded, body: dict[str, Any]) -> list[str]:
    by_id = {value: key for key, value in seeded.findings.items()}
    return [by_id[item["id"]] for item in body["items"]]


async def test_findings_come_by_severity_then_most_recent(seeded: Seeded) -> None:
    body = (await seeded.get()).json()

    assert labels(seeded, body) == [
        "critico",
        "alto-reciente",
        "alto-viejo",
        "cors",
        "borrada",
        "bajo",
        "aceptado",
    ]
    assert (body["total"], body["page"], body["page_size"]) == (7, 1, 20)


async def test_a_summary(seeded: Seeded) -> None:
    body = (await seeded.get("?severity=medium")).json()

    [cors] = body["items"]
    assert cors == {
        "id": seeded.findings["cors"],
        "module": "configuration",
        "finding_type": "configuration.cors_wildcard",
        "title": "Hallazgo cors",
        "severity": "medium",
        "owasp_category": "API1:2023",
        "cwe": "CWE-639",
        "status": "resolved",
        "operation": None,
        "identity": {
            "id": seeded.matrix.identities["Anónimo"],
            "name": "Anónimo",
            "deleted": False,
        },
        "detected_at": "2026-11-16T18:03:00Z",
        "last_detected_at": "2026-11-16T18:03:00Z",
        "resolved_at": "2026-11-16T18:40:00Z",
        "first_run": {"id": seeded.runs[0], "number": 1},
        "last_run": {"id": seeded.runs[0], "number": 1},
    }


async def test_filters(seeded: Seeded) -> None:
    open_ = (await seeded.get("?status=new&status=persistent&status=regression")).json()
    high = (await seeded.get("?severity=critical&severity=high")).json()
    configuration = (await seeded.get("?module=configuration")).json()
    second_run = (await seeded.get(f"?run_id={seeded.runs[1]}")).json()
    cell = (
        await seeded.get(
            f"?operation_id={seeded.matrix.operations[('GET', '/orders')]}"
            f"&identity_id={seeded.matrix.identities['Cliente B']}"
        )
    ).json()
    unknown_run = (await seeded.get(f"?run_id={uuid.uuid4()}")).json()

    assert labels(seeded, open_) == ["critico", "alto-reciente", "alto-viejo", "bajo"]
    assert labels(seeded, high) == ["critico", "alto-reciente", "alto-viejo"]
    assert labels(seeded, configuration) == ["cors"]
    assert labels(seeded, second_run) == ["critico", "alto-reciente", "alto-viejo"]
    assert labels(seeded, cell) == ["alto-reciente"]
    assert unknown_run == {"items": [], "total": 0, "page": 1, "page_size": 20}


async def test_pages_do_not_overlap(seeded: Seeded) -> None:
    pages = [(await seeded.get(f"?page={page}&page_size=3")).json() for page in (1, 2, 3)]

    assert [len(body["items"]) for body in pages] == [3, 3, 1]
    assert [label for body in pages for label in labels(seeded, body)] == labels(
        seeded, (await seeded.get()).json()
    )


async def test_a_dismissed_finding(seeded: Seeded) -> None:
    body = (await seeded.get(f"/{seeded.findings['aceptado']}")).json()

    assert body["status"] == "accepted_risk"
    assert body["dismissal"] == {
        "reason": "false_positive",
        "justification": "Es un dato público.",
        "dismissed_at": "2026-11-16T19:40:00Z",
    }
    assert body["history"][-1] == {
        "from_status": "new",
        "to_status": "accepted_risk",
        "reason": "false_positive",
        "run": None,  # the analyst did it
        "justification": "Es un dato público.",
        "occurred_at": "2026-11-16T19:40:00Z",
    }


async def test_a_finding_of_a_deleted_identity(seeded: Seeded) -> None:
    body = (await seeded.get(f"/{seeded.findings['borrada']}")).json()

    assert (body["status"], body["resolution_reason"]) == ("resolved", "identity_deleted")
    assert body["identity"]["deleted"] is True
    assert [e["reason"] for e in body["history"]] == ["detected", "identity_deleted"]


async def test_the_evidence_keeps_the_module_context_apart(seeded: Seeded) -> None:
    body = (await seeded.get(f"/{seeded.findings['alto-viejo']}")).json()

    evidence = body["last_occurrence"]["evidence"]
    assert evidence == {
        "request": {"method": "GET", "url": "https://api/x", "headers": {}, "body": None},
        "response": {
            "status_code": 200,
            "headers": {"content-type": "text/plain"},
            "body": "<script>alert(1)</script>",  # untrusted: returned as is, shown as text
            "body_truncated": True,
        },
        "context": {"control_identity": "raiz"},
    }
    assert body["last_occurrence"]["run"] == {"id": seeded.runs[1], "number": 2}
    assert [(e["to_status"], e["run"]["number"]) for e in body["history"]] == [
        ("new", 1),
        ("persistent", 2),
    ]


async def test_occurrences_most_recent_run_first(seeded: Seeded) -> None:
    url = f"/{seeded.findings['alto-viejo']}/occurrences"

    body = (await seeded.get(url)).json()
    second_page = (await seeded.get(f"{url}?page=2&page_size=1")).json()

    assert [item["run"]["number"] for item in body["items"]] == [2, 1]
    assert (body["total"], body["page_size"]) == (2, 10)
    assert [item["run"]["number"] for item in second_page["items"]] == [1]


@pytest.mark.parametrize(
    "suffix",
    [
        "?status=new&status=new",
        "?severity=urgent",
        "?module=sql",
        "?page_size=101",
        "?run_id=uno",
        "/no-es-uuid",
    ],
)
async def test_invalid_queries(seeded: Seeded, suffix: str) -> None:
    assert (await seeded.get(suffix)).status_code == 422


async def test_too_many_occurrences_per_page(seeded: Seeded) -> None:
    response = await seeded.get(f"/{seeded.findings['bajo']}/occurrences?page_size=21")

    assert response.status_code == 422


# ------------------------------------------------------------------ isolation (RN-02)


async def test_findings_of_another_analyst_or_project_are_not_found(
    seeded: Seeded, ana: Analyst, new_analyst: Any
) -> None:
    other: Analyst = new_analyst()
    await other.accept_terms()
    sibling = await other.create()
    finding = seeded.findings["critico"]

    responses = [
        await seeded.get(analyst=other),
        await seeded.get(f"/{finding}", analyst=other),
        await seeded.get(f"/{finding}/occurrences", analyst=other),
        await other.request("GET", f"{findings_url(sibling['id'])}/{finding}"),
        await seeded.get(f"/{uuid.uuid4()}"),
        await seeded.get(f"/{uuid.uuid4()}/occurrences"),
    ]
    own_sibling = (
        await ana.request("GET", findings_url((await ana.create(name="Otra API"))["id"]))
    ).json()

    assert [r.status_code for r in responses] == [404] * 6
    assert {r.json()["code"] for r in responses} == {"resource.not_found"}
    assert own_sibling["total"] == 0  # another project of the same analyst sees none


# ------------------------------------------------------------------ dismissal (CU-16, RF-70)


def dismissal(seeded: Seeded, label: str) -> str:
    return f"{seeded.url}/{seeded.findings[label]}/dismissal"


async def dismiss(seeded: Seeded, label: str, **body: Any) -> Any:
    payload = {"reason": "accepted_risk", "justification": "Lo cubre el WAF.", **body}
    return await seeded.project.analyst.request("POST", dismissal(seeded, label), json=payload)


async def test_accepting_the_risk_of_an_open_finding(seeded: Seeded) -> None:
    response = await dismiss(seeded, "critico", justification="  Lo cubre el WAF.\n\tRevisar.  ")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "accepted_risk"
    event = body["history"][-1]
    assert event == {
        "from_status": "new",
        "to_status": "accepted_risk",
        "reason": "accepted",
        "run": None,  # the analyst did it
        "justification": "Lo cubre el WAF.\n\tRevisar.",  # trimmed, lines kept
        "occurred_at": event["occurred_at"],
    }
    assert body["dismissal"] == {
        "reason": "accepted_risk",
        "justification": "Lo cubre el WAF.\n\tRevisar.",
        "dismissed_at": event["occurred_at"],
    }
    assert body == (await seeded.get(f"/{seeded.findings['critico']}")).json()
    still_open = (await seeded.get("?status=new&status=persistent&status=regression")).json()
    assert "critico" not in labels(seeded, still_open)


async def test_a_dismissal_and_its_revert_are_audited(seeded: Seeded, owner: AsyncEngine) -> None:
    """RN-09: the reason and the finding, never the justification (RF-83)."""
    finding = seeded.findings["critico"]
    await dismiss(seeded, "critico", reason="false_positive", justification="Texto del analista")
    await seeded.project.analyst.request("DELETE", dismissal(seeded, "critico"))

    entries = [
        e
        for e in await audit_entries(owner, project_id=seeded.project.id)
        if e.action.startswith("finding_")
    ]

    assert [(e.action, e.details) for e in entries] == [
        ("finding_dismissed", {"finding_id": finding, "dismissal_reason": "false_positive"}),
        ("finding_dismissal_reverted", {"finding_id": finding}),
    ]
    assert "Texto del analista" not in repr([e.details for e in entries])


@pytest.mark.parametrize("label", ["alto-viejo", "bajo"])  # persistent and new
async def test_marking_a_false_positive(seeded: Seeded, label: str) -> None:
    body = (await dismiss(seeded, label, reason="false_positive")).json()

    assert body["dismissal"]["reason"] == "false_positive"
    assert body["history"][-1]["reason"] == "false_positive"


@pytest.mark.parametrize("label", ["cors", "aceptado", "borrada"])  # resolved or already accepted
async def test_only_an_open_finding_is_dismissed(seeded: Seeded, label: str) -> None:
    before = (await seeded.get(f"/{seeded.findings[label]}")).json()

    response = await dismiss(seeded, label)

    assert response.status_code == 409
    assert response.json()["code"] == "finding.not_open"
    assert (await seeded.get(f"/{seeded.findings[label]}")).json() == before


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"justification": "   \n\t "}, "validation.required"),  # RN-09: blank is missing
        ({"justification": None}, "validation.format"),
        ({"justification": "a" * 2001}, "validation.length"),
        ({"justification": "con\x00nulo"}, "validation.format"),
        ({"reason": "won't_fix"}, "validation.format"),
    ],
)
async def test_invalid_dismissals(seeded: Seeded, body: dict[str, Any], code: str) -> None:
    response = await dismiss(seeded, "critico", **body)

    assert response.status_code == 422, response.text
    assert [error["code"] for error in response.json()["errors"]] == [code]


async def test_a_dismissal_needs_a_justification(seeded: Seeded) -> None:
    response = await seeded.project.analyst.request(
        "POST", dismissal(seeded, "critico"), json={"reason": "accepted_risk"}
    )

    assert response.status_code == 422
    assert response.json()["errors"][0] == {
        "field": "justification",
        "code": "validation.required",
        "message": "Este campo es obligatorio.",
    }


async def test_reverting_a_dismissal(seeded: Seeded) -> None:
    response = await seeded.project.analyst.request("DELETE", dismissal(seeded, "aceptado"))

    assert response.status_code == 204
    assert response.content == b""
    body = (await seeded.get(f"/{seeded.findings['aceptado']}")).json()
    assert (body["status"], body["dismissal"]) == ("persistent", None)  # whatever it was before
    assert body["history"][-1] == {
        "from_status": "accepted_risk",
        "to_status": "persistent",
        "reason": "reverted",
        "run": None,
        "justification": None,
        "occurred_at": body["history"][-1]["occurred_at"],
    }
    assert [e["reason"] for e in body["history"]] == ["detected", "false_positive", "reverted"]


@pytest.mark.parametrize("label", ["critico", "cors"])  # open and resolved
async def test_only_a_dismissed_finding_is_reverted(seeded: Seeded, label: str) -> None:
    response = await seeded.project.analyst.request("DELETE", dismissal(seeded, label))

    assert response.status_code == 409
    assert response.json()["code"] == "finding.not_dismissed"


async def test_dismissing_the_last_open_finding_concludes_the_project(seeded: Seeded) -> None:
    """RF-73: a completed run and no open finding."""
    project = f"/projects/{seeded.project.id}"
    analyst = seeded.project.analyst

    for label in ("critico", "alto-reciente", "alto-viejo"):
        assert (await dismiss(seeded, label)).status_code == 200
    almost = (await analyst.request("GET", project)).json()
    await dismiss(seeded, "bajo")
    concluded = (await analyst.request("GET", project)).json()
    await analyst.request("DELETE", dismissal(seeded, "bajo"))
    reopened = (await analyst.request("GET", project)).json()

    assert (almost["concluded"], concluded["concluded"], reopened["concluded"]) == (
        False,
        True,
        False,
    )


async def test_dismissing_another_analysts_finding_is_not_found(
    seeded: Seeded, new_analyst: Any
) -> None:
    other: Analyst = new_analyst()
    await other.accept_terms()
    body = {"reason": "accepted_risk", "justification": "Mío."}
    missing = f"{seeded.url}/{uuid.uuid4()}/dismissal"

    responses = [
        await other.request("POST", dismissal(seeded, "critico"), json=body),
        await other.request("DELETE", dismissal(seeded, "aceptado")),
        await seeded.project.analyst.request("POST", missing, json=body),
        await seeded.project.analyst.request("DELETE", missing),
    ]

    assert [r.status_code for r in responses] == [404] * 4
    assert (await seeded.get(f"/{seeded.findings['critico']}")).json()["status"] == "new"
    assert (await seeded.get(f"/{seeded.findings['aceptado']}")).json()["status"] == (
        "accepted_risk"
    )


async def test_an_accepted_finding_detected_again_stays_accepted(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
) -> None:
    """CU-16 and CU-17 through the API: accept, run again, revert, run again (ADR-014)."""
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    url = findings_url(project.id)
    await run_lab(scanner, project, lab)
    finding = (await ana.request("GET", url)).json()["items"][0]["id"]
    body = {"reason": "accepted_risk", "justification": "Mitigado en el gateway."}
    assert (await ana.request("POST", f"{url}/{finding}/dismissal", json=body)).status_code == 200

    await run_lab(scanner, project, lab)
    accepted = (await ana.request("GET", f"{url}/{finding}")).json()
    await ana.request("DELETE", f"{url}/{finding}/dismissal")
    await run_lab(scanner, project, lab)
    reopened = (await ana.request("GET", f"{url}/{finding}")).json()

    assert accepted["status"] == "accepted_risk"
    assert accepted["last_run"]["number"] == 2  # detected again: a new occurrence
    assert accepted["dismissal"]["justification"] == "Mitigado en el gateway."
    assert reopened["status"] == "persistent"
    assert [(e["reason"], e["run"] is None) for e in reopened["history"]] == [
        ("detected", False),
        ("accepted", True),
        ("reverted", True),
    ]
