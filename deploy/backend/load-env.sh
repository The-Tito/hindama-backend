#!/usr/bin/env bash
# Writes the backend's environment file from SSM Parameter Store (architecture 3.1; ADR-007).
#
# Runs at every boot, as root, with the instance role (it may read only /hindama/backend/*). Each
# parameter becomes a variable: /hindama/backend/api-db-password -> HINDAMA_API_DB_PASSWORD.
# The file lives in /run (tmpfs, gone at shutdown), 0600: the secrets never touch the disk.
# It prints names only, never values.
set -euo pipefail
umask 077

REGION="${AWS_REGION:-us-east-1}"
PREFIX="/hindama/backend/"
OUT="${HINDAMA_ENV_FILE:-/run/hindama/backend.env}"

mkdir -p "$(dirname "$OUT")"
tmp="$(mktemp "$(dirname "$OUT")/.backend.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

aws ssm get-parameters-by-path --region "$REGION" --path "$PREFIX" --with-decryption \
  --query 'Parameters[].[Name,Value]' --output json |
  python3 -c '
import json, re, sys

prefix, out = sys.argv[1], sys.argv[2]
names = []
with open(out, "w") as env:
    for name, value in json.load(sys.stdin):
        key = name.removeprefix(prefix)
        if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", key):
            sys.exit(f"nombre de parámetro inválido: {name}")
        if "\x27" in value or "\n" in value:
            sys.exit(f"valor no admitido (comilla simple o salto de línea) en {name}")
        variable = "HINDAMA_" + key.upper().replace("-", "_")
        env.write(f"{variable}=\x27{value}\x27\n")  # single quotes: Compose reads it literally
        names.append(variable)
print("variables:", " ".join(sorted(names)))
' "$PREFIX" "$tmp"

# The private IP comes from the instance metadata (IMDSv2), not from SSM.
token="$(curl -fsS -X PUT http://169.254.169.254/latest/api/token \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')"
private_ip="$(curl -fsS -H "X-aws-ec2-metadata-token: $token" \
  http://169.254.169.254/latest/meta-data/local-ipv4)"
echo "HINDAMA_PRIVATE_IP='$private_ip'" >>"$tmp"

mv "$tmp" "$OUT"
trap - EXIT
echo "escrito $OUT"
