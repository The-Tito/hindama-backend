-- Roles and database of Hindama in RDS (hindama-docs/02-datos/modelo.md 5.3), run once by the
-- master user, which is not a superuser in RDS (CREATEROLE and CREATEDB only). The local
-- equivalent is docker/postgres/init/01-roles.sh. Table privileges are granted by the migrations.
--
-- Passwords come from the environment (\getenv, psql 15+), never from the command line.
-- `hindama_backup` exists because the migrations grant it read access, but it cannot log in and
-- has no BYPASSRLS (that needs a superuser): in RDS the backups are its own automated snapshots
-- (architecture 3.1).

\set ON_ERROR_STOP on
\getenv migrations_pw HINDAMA_MIGRATIONS_DB_PASSWORD
\getenv api_pw HINDAMA_API_DB_PASSWORD
\getenv scanner_pw HINDAMA_SCANNER_DB_PASSWORD

-- Owner of the schema: used only by Alembic.
CREATE ROLE hindama_migrations LOGIN PASSWORD :'migrations_pw';
-- Application roles: no CREATE, no ownership; Row-Level Security applies to them (ADR-013).
CREATE ROLE hindama_api LOGIN PASSWORD :'api_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE hindama_scanner LOGIN PASSWORD :'scanner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE hindama_backup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

-- PostgreSQL 16: to give objects to a role, the master must be able to act as it. Only for
-- this script: it is revoked at the end.
GRANT hindama_migrations TO CURRENT_USER;

CREATE DATABASE hindama OWNER hindama_migrations;

\connect hindama
-- Nobody connects or creates objects unless explicitly allowed.
REVOKE ALL ON DATABASE hindama FROM PUBLIC;
GRANT CONNECT ON DATABASE hindama TO hindama_migrations, hindama_api, hindama_scanner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO hindama_migrations;

\connect postgres
REVOKE hindama_migrations FROM CURRENT_USER;
