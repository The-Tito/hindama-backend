#!/usr/bin/env bash
# Creates the Cognito User Pool of one environment (deploy/PROCEDIMIENTO.md, section 2).
#
#   AWS_PROFILE=hindama deploy/cognito/create-user-pool.sh dev
#
# Creates the pool (user-pool.json), the `administradores` group (RF-09) and the confidential app
# client for Next.js (app-client.json, ADR-005). The client secret goes straight to SSM Parameter
# Store as a SecureString: it is never printed nor passed as a command-line argument.
set -euo pipefail

ENVIRONMENT="${1:-}"
REGION="${AWS_REGION:-us-east-1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${ENVIRONMENT}" in
  dev | prod) ;;
  *)
    echo "Uso: $0 dev|prod" >&2
    exit 2
    ;;
esac

POOL_NAME="hindama-${ENVIRONMENT}"
ADMIN_GROUP="administradores"
SECRET_PARAMETER="/hindama/${ENVIRONMENT}/frontend/cognito-client-secret"
aws_cli() { aws --region "${REGION}" --output text "$@"; }

account="$(aws_cli sts get-caller-identity --query Account)"
caller="$(aws_cli sts get-caller-identity --query Arn)"
echo "Cuenta:    ${account}"
echo "Identidad: ${caller}"
echo "Región:    ${REGION}"
echo "Se creará el User Pool «${POOL_NAME}» y el parámetro ${SECRET_PARAMETER}."
if [[ "${caller}" == *":root" ]]; then
  echo "No uses la cuenta raíz: crea un usuario de IAM o usa IAM Identity Center." >&2
  exit 1
fi
read -r -p "¿Continuar? Escribe el nombre del pool para confirmar: " confirmation
if [[ "${confirmation}" != "${POOL_NAME}" ]]; then
  echo "Cancelado." >&2
  exit 1
fi

existing="$(aws_cli cognito-idp list-user-pools --max-results 60 \
  --query "UserPools[?Name=='${POOL_NAME}'].Id")"
if [[ -n "${existing}" && "${existing}" != "None" ]]; then
  echo "Ya existe un User Pool «${POOL_NAME}» (${existing}). No se crea otro." >&2
  exit 1
fi

pool_id="$(aws_cli cognito-idp create-user-pool \
  --cli-input-json "file://${HERE}/user-pool.json" \
  --pool-name "${POOL_NAME}" \
  --user-pool-tags "project=hindama,environment=${ENVIRONMENT}" \
  --query UserPool.Id)"
echo "User Pool creado: ${pool_id}"

aws_cli cognito-idp create-group \
  --user-pool-id "${pool_id}" \
  --group-name "${ADMIN_GROUP}" \
  --description "Administradores de Hindama (RF-09). Solo se asigna desde la consola." \
  --precedence 0 >/dev/null
echo "Grupo creado: ${ADMIN_GROUP}"

# The secret stays in a private temporary file and goes to SSM with file://, so it never shows up
# in the terminal, in the shell history or in the process list.
umask 077
secret_file="$(mktemp)"
trap 'rm -f "${secret_file}"' EXIT
client_id="$(aws --region "${REGION}" cognito-idp create-user-pool-client \
  --cli-input-json "file://${HERE}/app-client.json" \
  --user-pool-id "${pool_id}" \
  --query 'UserPoolClient.[ClientId,ClientSecret]' --output text |
  { read -r id secret; printf '%s' "${secret}" >"${secret_file}"; echo "${id}"; })"
echo "Cliente creado: ${client_id}"

aws_cli ssm put-parameter \
  --name "${SECRET_PARAMETER}" \
  --type SecureString \
  --value "file://${secret_file}" \
  --tags "Key=project,Value=hindama" "Key=environment,Value=${ENVIRONMENT}" >/dev/null
echo "Secreto del cliente guardado en SSM: ${SECRET_PARAMETER}"

cat <<EOF

Listo. Valores para el .env del backend (no son secretos):

HINDAMA_COGNITO_REGION=${REGION}
HINDAMA_COGNITO_USER_POOL_ID=${pool_id}
HINDAMA_COGNITO_CLIENT_ID=${client_id}

El frontend lee el secreto del cliente desde ${SECRET_PARAMETER}.
EOF
