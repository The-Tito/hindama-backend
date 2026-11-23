"""`GET /projects/{project_id}/findings/export` (exportFindings): CU-19, RF-77, RN-11."""

from io import BytesIO
from typing import Any

import pytest
from fastapi import FastAPI
from openpyxl import load_workbook
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.scanner.execution import Scanner
from hindama.services import findings as findings_service
from hindama.services.finding_export import MEDIA_TYPE
from tests.integration.conftest import Analyst
from tests.integration.test_findings import SECRETS, findings_url
from tests.lab.scanning import lab_project, lab_scanner, run_lab
from tests.ownership import ScriptedChecker
from tests.servers import LocalServer


@pytest.fixture
def scanner(scanner_engine: AsyncEngine, app: FastAPI) -> Scanner:
    return lab_scanner(scanner_engine, app.state.credential_cipher, ScriptedChecker())


def rows_of(content: bytes) -> list[tuple[Any, ...]]:
    sheet = load_workbook(BytesIO(content))["Hallazgos"]
    return [tuple(row) for row in sheet.iter_rows(values_only=True)]


async def test_the_workbook_has_the_findings_of_the_list(
    ana: Analyst, vulnerable_lab: tuple[LocalServer, FastAPI], scanner: Scanner
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    await run_lab(scanner, project, lab)
    url = findings_url(project.id)
    listed = (await ana.request("GET", url, params={"page_size": 100})).json()

    response = await ana.request("GET", f"{url}/export")

    assert response.status_code == 200
    assert response.headers["content-type"] == MEDIA_TYPE
    assert response.headers["content-disposition"] == 'attachment; filename="hallazgos.xlsx"'
    header, *rows = rows_of(response.content)
    assert header[:3] == ("Título", "Severidad", "Estado")
    assert len(rows) == listed["total"] == 5
    assert [(row[0], row[4], row[8], row[9]) for row in rows] == [
        (
            item["title"],
            item["finding_type"],
            item["operation"]["path"] if item["operation"] else "Toda la API",
            item["identity"]["name"],
        )
        for item in listed["items"]
    ]
    first = rows[0]
    assert (first[1], first[2], first[3]) == ("Alta", "Nuevo", "Acceso a objetos")
    # RN-11: no credential of the lab, not even in the compressed parts of the file.
    text = "\n".join(str(value) for row in rows for value in row)
    assert not [secret for secret in SECRETS if secret in text]

    only_resolved = await ana.request("GET", f"{url}/export", params={"status": "resolved"})
    assert rows_of(only_resolved.content)[1:] == []


async def test_too_many_findings_ask_to_filter(
    ana: Analyst,
    vulnerable_lab: tuple[LocalServer, FastAPI],
    scanner: Scanner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, lab = vulnerable_lab
    project = await lab_project(ana, server, lab)
    await run_lab(scanner, project, lab)
    monkeypatch.setattr(findings_service, "EXPORT_LIMIT", 4)
    url = f"{findings_url(project.id)}/export"

    too_many = await ana.request("GET", url)
    filtered = await ana.request("GET", url, params={"identity_id": project.identities["ana"]})

    assert too_many.status_code == 422
    assert too_many.json()["code"] == "finding.export_too_large"
    assert filtered.status_code == 200


async def test_a_project_of_another_analyst_is_not_found(ana: Analyst, new_analyst: Any) -> None:
    created = await ana.create()
    beto: Analyst = new_analyst()
    await beto.accept_terms()

    response = await beto.request("GET", f"{findings_url(created['id'])}/export")

    assert response.status_code == 404
    assert response.json()["code"] == "resource.not_found"


async def test_an_empty_project_gives_only_the_header(ana: Analyst) -> None:
    created = await ana.create()

    response = await ana.request("GET", f"{findings_url(created['id'])}/export")

    assert response.status_code == 200
    assert len(rows_of(response.content)) == 1


async def test_the_detail_still_answers_next_to_the_export(ana: Analyst) -> None:
    created = await ana.create()
    url = findings_url(created["id"])

    unknown = await ana.request("GET", f"{url}/0192e3a0-aaaa-7000-8000-000000000999")

    assert unknown.status_code == 404
