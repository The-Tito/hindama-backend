"""row level security and privileges

Written by hand: autogenerate detects none of this (modelo.md, sections 5 and 7.4; ADR-013).

- Row-Level Security on every table with project data, for `hindama_api` (owner only) and
  `hindama_scanner` (all rows). The tables belong to `hindama_migrations`, which is not used at
  runtime, so FORCE ROW LEVEL SECURITY is not needed.
- Privileges per database role (modelo.md, section 5.3).
- `audit_log` is immutable: a trigger rejects UPDATE and TRUNCATE, and DELETE of rows inside the
  retention period. `purge_audit_log()` deletes the expired ones (RF-83, RF-90).

Revision ID: 369b4dfef139
Revises: 71fa49840e15
Create Date: 2026-10-30 12:05:41.512302

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "369b4dfef139"
down_revision: str | Sequence[str] | None = "71fa49840e15"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

API = "hindama_api"
SCANNER = "hindama_scanner"
BACKUP = "hindama_backup"
APP_ROLES = f"{API}, {SCANNER}, {BACKUP}"

AUDIT_RETENTION = "6 months"  # modelo.md 7.4; also stated in the privacy notice

# Every table that carries `project_id -> projects.id`. Their policy delegates to the one of
# `projects`, which already filters by owner.
PROJECT_CHILD_TABLES = (
    "contract_versions",
    "operations",
    "operation_versions",
    "identities",
    "resources",
    "runs",
    "results",
    "created_resources",
    "findings",
    "finding_occurrences",
    "finding_events",
)
METRIC_TABLES = ("finding_metrics", "daily_metrics")

# Settings fixed by the API with set_config(..., true) at the start of each transaction. Without
# them current_setting(..., true) is NULL or '' and the policies match nothing (fail closed).
CURRENT_SUB = "current_setting('app.cognito_sub', true)"
CURRENT_USER_ID = "NULLIF(current_setting('app.user_id', true), '')::uuid"
CURRENT_ROLE = "current_setting('app.role', true)"

API_POLICIES = {
    "users": f"cognito_sub = {CURRENT_SUB}",
    "projects": f"owner_id = {CURRENT_USER_ID}",
    **{
        table: "EXISTS (SELECT 1 FROM projects p WHERE p.id = project_id)"
        for table in PROJECT_CHILD_TABLES
    },
}

API_GRANTS = {
    **{table: "SELECT, INSERT, UPDATE, DELETE" for table in API_POLICIES},
    # History is append-only (RF-72, RF-83).
    "finding_events": "SELECT, INSERT",
    "audit_log": "SELECT",  # INSERT is granted per column, below
    **{table: "SELECT, INSERT, UPDATE" for table in METRIC_TABLES},
}

# The scanner reads the configuration of any project and writes only what a run produces. It does
# not receive user input to choose a project, so its policies allow every row (modelo.md 5.1).
SCANNER_GRANTS = {
    "projects": "SELECT",
    "contract_versions": "SELECT",
    "operations": "SELECT",
    "operation_versions": "SELECT",
    "identities": "SELECT",
    "resources": "SELECT",
    "runs": "SELECT, UPDATE",  # the API creates runs; the scanner moves them through their states
    "results": "SELECT, INSERT",
    "created_resources": "SELECT, INSERT, UPDATE",
    "findings": "SELECT, INSERT, UPDATE",
    "finding_occurrences": "SELECT, INSERT",
    "finding_events": "SELECT, INSERT",
    **{table: "SELECT, INSERT, UPDATE" for table in METRIC_TABLES},
}
SCANNER_POLICY_TABLES = tuple(table for table in SCANNER_GRANTS if table not in METRIC_TABLES)
# Column-level UPDATE: verification before each run (RF-20) and identity status (RF-33).
SCANNER_COLUMN_UPDATES = {
    "projects": (
        "verification_status",
        "verification_method",
        "verified_at",
        "verified_host",
        "updated_at",
    ),
    "identities": ("status",),
}

# Nobody chooses `id` or `occurred_at`: an event cannot be backdated into the purge window.
AUDIT_LOG_INSERT_COLUMNS = (
    "user_id",
    "action",
    "project_id",
    "host_hmac",
    "hmac_version",
    "source_ip",
    "details",
)

ALL_TABLES = (
    "users",
    "projects",
    *PROJECT_CHILD_TABLES,
    "audit_log",
    *METRIC_TABLES,
)


def upgrade() -> None:
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLES}")
    for table in ALL_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")

    # --- hindama_api: owner-only access ------------------------------------------------------
    for table, condition in API_POLICIES.items():
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # Same expression in USING and WITH CHECK: no reading nor writing another owner's rows.
        op.execute(
            f"CREATE POLICY api_owner ON {table} FOR ALL TO {API}"
            f" USING ({condition}) WITH CHECK ({condition})"
        )
    for table, privileges in API_GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {API}")

    # --- hindama_scanner: every project, limited by privileges and composite keys ------------
    for table in SCANNER_POLICY_TABLES:
        op.execute(f"CREATE POLICY scanner_all ON {table} FOR ALL TO {SCANNER} USING (true)")
    for table, privileges in SCANNER_GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {SCANNER}")
    for table, columns in SCANNER_COLUMN_UPDATES.items():
        op.execute(f"GRANT UPDATE ({', '.join(columns)}) ON {table} TO {SCANNER}")

    # --- audit_log: everyone may write, only the administrator reads (RF-82, RF-83) -----------
    op.execute("ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY api_insert ON audit_log FOR INSERT TO {API} WITH CHECK (true)")
    op.execute(
        f"CREATE POLICY api_admin_select ON audit_log FOR SELECT TO {API}"
        f" USING ({CURRENT_ROLE} = 'admin')"
    )
    op.execute(
        f"CREATE POLICY scanner_insert ON audit_log FOR INSERT TO {SCANNER} WITH CHECK (true)"
    )
    op.execute(
        f"GRANT INSERT ({', '.join(AUDIT_LOG_INSERT_COLUMNS)}) ON audit_log TO {API}, {SCANNER}"
    )

    op.execute(f"""
        CREATE FUNCTION audit_log_immutable() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND OLD.occurred_at < now() - interval '{AUDIT_RETENTION}' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'audit_log is immutable (%)', TG_OP;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER audit_log_immutable_rows
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION audit_log_immutable()
    """)
    op.execute("""
        CREATE TRIGGER audit_log_immutable_truncate
        BEFORE TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable()
    """)

    # Runs as its owner (hindama_migrations), which RLS does not filter. Fixed search_path so a
    # caller cannot shadow `audit_log` or `now()` with its own objects.
    op.execute(f"""
        CREATE FUNCTION purge_audit_log() RETURNS bigint
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            WITH purged AS (
                DELETE FROM public.audit_log
                WHERE occurred_at < now() - interval '{AUDIT_RETENTION}'
                RETURNING 1
            )
            SELECT count(*) FROM purged
        $$
    """)
    op.execute("REVOKE ALL ON FUNCTION purge_audit_log() FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION purge_audit_log() TO {SCANNER}")

    # --- hindama_backup: reads everything (BYPASSRLS) for pg_dump -----------------------------
    op.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {BACKUP}")


def downgrade() -> None:
    op.execute(f"REVOKE SELECT ON ALL TABLES IN SCHEMA public FROM {BACKUP}")
    op.execute("DROP FUNCTION purge_audit_log()")
    op.execute("DROP TRIGGER audit_log_immutable_truncate ON audit_log")
    op.execute("DROP TRIGGER audit_log_immutable_rows ON audit_log")
    op.execute("DROP FUNCTION audit_log_immutable()")

    for policy in ("api_insert", "api_admin_select", "scanner_insert"):
        op.execute(f"DROP POLICY {policy} ON audit_log")
    op.execute("ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY")

    for table in SCANNER_POLICY_TABLES:
        op.execute(f"DROP POLICY scanner_all ON {table}")
    for table in API_POLICIES:
        op.execute(f"DROP POLICY api_owner ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    for table in ALL_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM {API}, {SCANNER}")
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {APP_ROLES}")
