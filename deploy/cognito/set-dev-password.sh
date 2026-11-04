#!/usr/bin/env bash
# Sets a permanent password for a test account of the DEVELOPMENT User Pool:
#
#   deploy/cognito/set-dev-password.sh ana@ejemplo.com
#
# For accounts created in the console before the frontend has its sign-up form. The password is
# read without echo and reaches the CLI through a private file, never as an argument.
set -euo pipefail

EMAIL="${1:?Uso: $0 correo}"
REGION="${AWS_REGION:-us-east-1}"
: "${HINDAMA_COGNITO_USER_POOL_ID:?Carga el .env del backend: falta HINDAMA_COGNITO_USER_POOL_ID}"

pool_name="$(aws --region "${REGION}" cognito-idp describe-user-pool \
  --user-pool-id "${HINDAMA_COGNITO_USER_POOL_ID}" --query UserPool.Name --output text)"
if [[ "${pool_name}" != "hindama-dev" ]]; then
  echo "Solo para el pool de desarrollo (este es «${pool_name}»)." >&2
  exit 1
fi

read -r -s -p "Contraseña nueva de ${EMAIL}: " password </dev/tty
echo >&2

umask 077
input="$(mktemp)"
trap 'rm -f "${input}"' EXIT
python3 -c '
import json, sys
path, pool_id, email = sys.argv[1:]
password = sys.stdin.read().rstrip("\n")
with open(path, "w") as f:
    json.dump({"UserPoolId": pool_id, "Username": email, "Password": password, "Permanent": True}, f)
' "${input}" "${HINDAMA_COGNITO_USER_POOL_ID}" "${EMAIL}" <<<"${password}"
unset password

if ! output="$(aws --region "${REGION}" cognito-idp admin-set-user-password \
  --cli-input-json "file://${input}" 2>&1)"; then
  case "${output}" in
    *PasswordHistoryPolicyViolationException*)
      echo "Esa contraseña ya se usó (Cognito recuerda las últimas 5, incluida la temporal)." >&2 ;;
    *InvalidPasswordException*)
      echo "No cumple la política: 12 caracteres con mayúsculas, minúsculas, números y símbolos." >&2 ;;
    *) echo "${output}" >&2 ;;
  esac
  exit 1
fi
echo "Contraseña actualizada para ${EMAIL}."
