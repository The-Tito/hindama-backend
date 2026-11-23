"""The findings list as an Excel workbook (CU-19, RF-77).

Untrusted text: paths and names come from the analyst's contract and configuration, so every text
cell is stored as text, never as a formula, even if it starts with `=`, `+`, `-` or `@` (CWE-1236).
No evidence and no credentials (RN-11): only the classification and the follow-up of each finding.
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from io import BytesIO

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE, Cell, MergedCell
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from hindama.models.enums import FindingStatus, Module, Severity
from hindama.repositories.findings import FindingRow

MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
FILENAME = "hallazgos.xlsx"
SHEET = "Hallazgos"
DATE_FORMAT = "yyyy-mm-dd hh:mm"
WHOLE_API = "Toda la API"

SEVERITIES = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Media",
    Severity.LOW: "Baja",
    Severity.INFO: "Informativa",
}
STATUSES = {
    FindingStatus.NEW: "Nuevo",
    FindingStatus.PERSISTENT: "Persistente",
    FindingStatus.REGRESSION: "Regresión",
    FindingStatus.RESOLVED: "Resuelto",
    FindingStatus.ACCEPTED_RISK: "Riesgo aceptado",
}
MODULES = {
    Module.AUTHENTICATION: "Autenticación",
    Module.CONFIGURATION: "Configuración",
    Module.OBJECT_ACCESS: "Acceso a objetos",
    Module.FUNCTION_ACCESS: "Acceso a funciones",
    Module.PROPERTY_ACCESS: "Propiedades",
    Module.RESOURCE_CONSUMPTION: "Consumo de recursos",
    Module.SQL_INJECTION: "Inyección SQL",
}

# (header, width in characters)
COLUMNS = (
    ("Título", 50),
    ("Severidad", 12),
    ("Estado", 16),
    ("Módulo", 20),
    ("Tipo de falla", 36),
    ("Categoría OWASP", 16),
    ("CWE", 10),
    ("Método", 9),
    ("Ruta", 40),
    ("Identidad", 24),
    ("Detectado (UTC)", 17),
    ("Última detección (UTC)", 17),
    ("Resuelto (UTC)", 17),
    ("Recomendación", 60),
)

Value = str | datetime | None


def _identity(row: FindingRow) -> str:
    name = row.identity.name
    return f"{name} (eliminada)" if row.identity.deleted_at is not None else name


def _values(row: FindingRow) -> tuple[Value, ...]:
    finding, operation = row.finding, row.operation
    return (
        finding.title,
        SEVERITIES[Severity(finding.severity)],
        STATUSES[FindingStatus(finding.status)],
        MODULES[Module(finding.module)],
        finding.finding_type,
        finding.owasp_category,
        finding.cwe,
        None if operation is None else operation.method,
        WHOLE_API if operation is None else operation.path,
        _identity(row),
        finding.detected_at,
        row.last_detected_at,
        finding.resolved_at,
        finding.recommendation,
    )


def _write(sheet: Worksheet, row: int, column: int, value: Value) -> Cell | MergedCell:
    cell = sheet.cell(row=row, column=column)
    if isinstance(value, datetime):
        # Excel has no time zones: the value is written in UTC, as the header says.
        cell.value = value.astimezone(UTC).replace(tzinfo=None)
        cell.number_format = DATE_FORMAT
    elif value is not None:
        # Assigning a string that starts with `=` makes it a formula: force the text type after.
        cell.value = ILLEGAL_CHARACTERS_RE.sub("", value)
        cell.data_type = "s"
    return cell


def workbook(rows: Sequence[FindingRow]) -> bytes:
    """One row per finding, in the order received (the same as `listFindings`)."""
    book = Workbook()
    book.properties.creator = "Hindama"
    sheet = book.active
    assert isinstance(sheet, Worksheet)  # noqa: S101 - a new Workbook always has one sheet
    sheet.title = SHEET
    bold = Font(bold=True)
    for column, (header, width) in enumerate(COLUMNS, start=1):
        _write(sheet, 1, column, header).font = bold
        sheet.column_dimensions[get_column_letter(column)].width = width
    for number, row in enumerate(rows, start=2):
        for column, value in enumerate(_values(row), start=1):
            _write(sheet, number, column, value)
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    buffer = BytesIO()
    book.save(buffer)
    return buffer.getvalue()
