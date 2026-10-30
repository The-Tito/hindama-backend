"""`users` (modelo.md, section 3.1).

Name, email and role are not stored: name and email live in Cognito (minimal personal data,
ADR-015) and the role comes from the `cognito:groups` claim on every request (RN-04).
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column

from hindama.models.base import Base, created_at, uuid_pk


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "(terms_accepted_at IS NULL) = (terms_version IS NULL)", name="terms_consistent"
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    cognito_sub: Mapped[str] = mapped_column(unique=True)
    terms_accepted_at: Mapped[datetime | None]
    terms_version: Mapped[str | None]
    created_at: Mapped[datetime] = created_at()
