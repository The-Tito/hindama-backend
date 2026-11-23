"""The Excel workbook of the findings (CU-19, RF-77): text is never a formula (CWE-1236)."""

import zipfile
from datetime import UTC, datetime, timedelta, timezone
from io import BytesIO
from uuid import uuid4

import pytest
from openpyxl import load_workbook

from hindama.models import Finding, Identity, Operation
from hindama.repositories.findings import FindingRow
from hindama.services.finding_export import COLUMNS, workbook

DETECTED = datetime(2026, 11, 23, 10, 30, tzinfo=timezone(timedelta(hours=-6)))


def row(
    *,
    title: str = "Acceso a un objeto de otra identidad",
    path: str | None = "/orders/{order_id}",
    identity: str = "ana",
    identity_deleted: bool = False,
    status: str = "new",
) -> FindingRow:
    finding = Finding(
        id=uuid4(),
        module="object_access",
        finding_type="object_access.unauthorized_read",
        severity="high",
        owasp_category="API1:2023",
        cwe="CWE-639",
        title=title,
        recommendation="Comprueba en el servidor que el objeto pertenece a quien lo pide.",
        status=status,
        detected_at=DETECTED,
        resolved_at=None,
    )
    operation = None if path is None else Operation(method="GET", path=path)
    who = Identity(name=identity, deleted_at=DETECTED if identity_deleted else None)
    return FindingRow(finding, operation, who, 1, 2, DETECTED + timedelta(hours=1))


def sheet_rows(content: bytes) -> list[tuple[object, ...]]:
    sheet = load_workbook(BytesIO(content))["Hallazgos"]
    return [tuple(cells) for cells in sheet.iter_rows(values_only=True)]


def test_one_row_per_finding_with_spanish_values_and_utc_dates() -> None:
    header, values = sheet_rows(workbook([row()]))

    assert header == tuple(name for name, _ in COLUMNS)
    assert values == (
        "Acceso a un objeto de otra identidad",
        "Alta",
        "Nuevo",
        "Acceso a objetos",
        "object_access.unauthorized_read",
        "API1:2023",
        "CWE-639",
        "GET",
        "/orders/{order_id}",
        "ana",
        datetime(2026, 11, 23, 16, 30, tzinfo=UTC).replace(tzinfo=None),  # 10:30 in UTC-6
        datetime(2026, 11, 23, 17, 30, tzinfo=UTC).replace(tzinfo=None),
        None,
        "Comprueba en el servidor que el objeto pertenece a quien lo pide.",
    )


def test_api_wide_findings_and_deleted_identities() -> None:
    _, values = sheet_rows(workbook([row(path=None, identity="beto", identity_deleted=True)]))

    assert (values[7], values[8], values[9]) == (None, "Toda la API", "beto (eliminada)")


@pytest.mark.parametrize(
    "dangerous",
    [
        '=HYPERLINK("https://evil.example","clic")',
        "+cmd|' /C calc'!A0",
        "-2+3",
        "@SUM(1+1)",
        "=1+1",
    ],
)
def test_text_that_looks_like_a_formula_stays_text(dangerous: str) -> None:
    content = workbook([row(path=dangerous, identity=dangerous)])

    _, values = sheet_rows(content)
    assert (values[8], values[9]) == (dangerous, dangerous)
    with zipfile.ZipFile(BytesIO(content)) as archive:
        sheet_xml = archive.read("xl/worksheets/sheet1.xml").decode()
    assert "<f>" not in sheet_xml and "<f " not in sheet_xml


def test_control_characters_are_removed() -> None:
    _, values = sheet_rows(workbook([row(identity="ana\x00\x07\x1b")]))

    assert values[9] == "ana"


def test_the_file_does_not_name_the_library() -> None:
    book = load_workbook(BytesIO(workbook([])))

    assert book.properties.creator == "Hindama"
    assert book.sheetnames == ["Hallazgos"]
