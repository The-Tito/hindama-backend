#!/usr/bin/env bash
# Prints an access token of the DEVELOPMENT User Pool, to try the API by hand:
#
#   TOKEN="$(deploy/cognito/get-dev-token.sh ana@ejemplo.com)"
#   curl -H "Authorization: Bearer ${TOKEN}" http://localhost:8000/me
#
# Logs in like Next.js does (USER_PASSWORD_AUTH with SECRET_HASH, ADR-005). The password is read
# without echo and the client secret is read from SSM; neither is printed. Only for `dev`: in
# production, tokens exist only inside the encrypted session cookie.
set -euo pipefail

EMAIL="${1:?Uso: $0 correo}"
REGION="${AWS_REGION:-us-east-1}"
SECRET_PARAMETER="/hindama/dev/frontend/cognito-client-secret"
: "${HINDAMA_COGNITO_CLIENT_ID:?Carga el .env del backend: falta HINDAMA_COGNITO_CLIENT_ID}"

read -r -s -p "Contraseña de ${EMAIL}: " password </dev/tty
echo >&2

secret="$(aws --region "${REGION}" ssm get-parameter --name "${SECRET_PARAMETER}" \
  --with-decryption --query Parameter.Value --output text)"

umask 077
input="$(mktemp)"
trap 'rm -f "${input}"' EXIT
# The secret and the password travel through stdin into a private file: they never appear in the
# process list. SECRET_HASH = Base64(HMAC-SHA256(client secret, username + client id)).
python3 -c '
import base64, hashlib, hmac, json, sys
path, client_id, email = sys.argv[1:]
secret, password = sys.stdin.read().split("\n", 1)
password = password.rstrip("\n")
digest = hmac.new(secret.encode(), (email + client_id).encode(), hashlib.sha256).digest()
with open(path, "w") as f:
    json.dump({
        "AuthFlow": "USER_PASSWORD_AUTH",
        "ClientId": client_id,
        "AuthParameters": {
            "USERNAME": email,
            "PASSWORD": password,
            "SECRET_HASH": base64.b64encode(digest).decode(),
        },
    }, f)
' "${input}" "${HINDAMA_COGNITO_CLIENT_ID}" "${EMAIL}" <<<"${secret}
${password}"
unset secret password

result="$(aws --region "${REGION}" cognito-idp initiate-auth --cli-input-json "file://${input}" \
  --query '[ChallengeName, AuthenticationResult.AccessToken]' --output text)"
read -r challenge token <<<"${result}"
if [[ "${challenge}" != "None" ]]; then
  echo "Cognito pide el paso «${challenge}» antes de entregar tokens." >&2
  if [[ "${challenge}" == "NEW_PASSWORD_REQUIRED" ]]; then
    echo "La cuenta aún tiene la contraseña temporal: corre set-dev-password.sh con una nueva." >&2
  fi
  exit 1
fi
printf '%s\n' "${token}"
