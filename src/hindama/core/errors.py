"""Domain errors.

Services raise these exceptions; the API layer turns them into Problem Details responses
(hindama-docs/03-api/convenciones.md, section 8). `code` is the stable contract with the frontend;
`title` and `detail` are Spanish fallback texts and must never contain internal details (RNF-07).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FieldIssue:
    """An error tied to one input field."""

    field: str | None
    code: str
    message: str


@dataclass(eq=False)
class AppError(Exception):
    """Base class of every error that reaches the client as a Problem."""

    code: str
    title: str
    detail: str
    status: int = 400
    errors: list[FieldIssue] = field(default_factory=list)
    # Extra Problem members defined by the contract for a specific error (e.g. `found`).
    extensions: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.code)


class NotFoundError(AppError):
    """The resource does not exist or belongs to another analyst; both look identical (RN-02)."""

    def __init__(self) -> None:
        super().__init__(
            code="resource.not_found",
            title="No encontrado",
            detail="El recurso no existe.",
            status=404,
        )


class ForbiddenError(AppError):
    def __init__(self, code: str, title: str, detail: str) -> None:
        super().__init__(code=code, title=title, detail=detail, status=403)


class ConflictError(AppError):
    def __init__(self, code: str, title: str, detail: str) -> None:
        super().__init__(code=code, title=title, detail=detail, status=409)


class UnprocessableError(AppError):
    """Field validation or business rule failure (422)."""

    def __init__(
        self,
        code: str,
        title: str,
        detail: str,
        errors: list[FieldIssue] | None = None,
        extensions: dict[str, object] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            title=title,
            detail=detail,
            status=422,
            errors=errors or [],
            extensions=extensions or {},
        )


class ServiceUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__(
            code="service.unavailable",
            title="Servicio no disponible",
            detail="Un servicio interno no responde. Intenta de nuevo en unos minutos.",
            status=503,
        )
