"""Data access: SQLAlchemy queries over the models.

Every query on project data starts from the current user's project (RN-02); the database also
enforces Row-Level Security (ADR-013)."""
