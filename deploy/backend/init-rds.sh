#!/usr/bin/env bash
# Runs rds-roles.sql against RDS, once, from the backend's EC2 (via Session Manager, as root).
#
# The master password is read from /hindama/backend-init/db-master-password, which the instance
# role may read only while the database is being initialized; afterwards the parameter is deleted
# (RDS can reset the master password whenever it is needed). Nothing is printed but the result.
set -euo pipefail
umask 077

REGION="${AWS_REGION:-us-east-1}"
DIR=/opt/hindama
MASTER_USER="${HINDAMA_DB_MASTER_USER:-hindama_admin}"

get() {
  aws ssm get-parameter --region "$REGION" --name "$1" --with-decryption \
    --query Parameter.Value --output text
}

PGHOST="$(get /hindama/backend/db-host)"
PGPASSWORD="$(get /hindama/backend-init/db-master-password)"
HINDAMA_MIGRATIONS_DB_PASSWORD="$(get /hindama/backend/migrations-db-password)"
HINDAMA_API_DB_PASSWORD="$(get /hindama/backend/api-db-password)"
HINDAMA_SCANNER_DB_PASSWORD="$(get /hindama/backend/scanner-db-password)"
export PGHOST PGPASSWORD HINDAMA_MIGRATIONS_DB_PASSWORD HINDAMA_API_DB_PASSWORD \
  HINDAMA_SCANNER_DB_PASSWORD

# `-e NAME` without a value passes the variable from this environment: no secret in `ps`.
docker run --rm -i \
  -e PGHOST -e PGPASSWORD -e PGUSER="$MASTER_USER" -e PGDATABASE=postgres \
  -e PGSSLMODE=verify-full -e PGSSLROOTCERT=/etc/hindama/rds-ca.pem \
  -e HINDAMA_MIGRATIONS_DB_PASSWORD -e HINDAMA_API_DB_PASSWORD -e HINDAMA_SCANNER_DB_PASSWORD \
  -v "$DIR/rds-ca.pem:/etc/hindama/rds-ca.pem:ro" \
  postgres:16-bookworm psql --quiet <"$DIR/rds-roles.sql"

echo "roles y base de datos creados en ${PGHOST%%.*}"
