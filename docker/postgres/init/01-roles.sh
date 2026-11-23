#!/usr/bin/env bash
# Creates the four database roles and the databases (hindama-docs/02-datos/modelo.md, section 5.3).
#
# Runs once, when the local PostgreSQL volume is created. In RDS, the master user runs the same
# statements once, following the deployment procedure. Table privileges are NOT granted here:
# migrations grant them, so they stay versioned next to the schema.
set -euo pipefail

: "${HINDAMA_MIGRATIONS_DB_PASSWORD:?missing}"
: "${HINDAMA_API_DB_PASSWORD:?missing}"
: "${HINDAMA_SCANNER_DB_PASSWORD:?missing}"
: "${HINDAMA_BACKUP_DB_PASSWORD:?missing}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v migrations_pw="$HINDAMA_MIGRATIONS_DB_PASSWORD" \
  -v api_pw="$HINDAMA_API_DB_PASSWORD" \
  -v scanner_pw="$HINDAMA_SCANNER_DB_PASSWORD" \
  -v backup_pw="$HINDAMA_BACKUP_DB_PASSWORD" <<'SQL'
-- Owner of the schema: used only by Alembic.
CREATE ROLE hindama_migrations LOGIN PASSWORD :'migrations_pw';
-- Application roles: no CREATE, no ownership; Row-Level Security applies to them (ADR-013).
CREATE ROLE hindama_api LOGIN PASSWORD :'api_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE hindama_scanner LOGIN PASSWORD :'scanner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
-- Backup: read-only, must see every row for pg_dump.
CREATE ROLE hindama_backup LOGIN PASSWORD :'backup_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;

-- Application database and a separate one for integration tests.
CREATE DATABASE hindama OWNER hindama_migrations;
CREATE DATABASE hindama_test OWNER hindama_migrations;
SQL

for db in hindama hindama_test; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" -v db="$db" <<'SQL'
-- Nobody connects or creates objects unless explicitly allowed.
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO hindama_migrations, hindama_api, hindama_scanner, hindama_backup;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO hindama_migrations;
SQL
done
