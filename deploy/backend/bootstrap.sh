#!/usr/bin/env bash
# User data of the backend's EC2: Amazon Linux 2023 on arm64 (architecture 3.1; ADR-002, ADR-011).
#
# Installs Docker and the Compose plugin (checksum verified), a 2 GB swap, the RDS certificate
# bundle and the deployment files of a pinned commit, then starts the backend with systemd. It is
# idempotent: running it again updates the files and restarts the service.
# Never logs secrets: those are read at boot by load-env.sh, with the instance role.
set -euo pipefail

# The commit whose deploy/backend/ files are installed (a full SHA, not a branch).
HINDAMA_REF="${HINDAMA_REF:-REPLACE_WITH_COMMIT_SHA}"
COMPOSE_VERSION="v5.7.0"
COMPOSE_SHA256="15861535d14e26555736b49376c95e14bfd94285366c8446bfac7156a972e76f"
RAW="https://raw.githubusercontent.com/The-Tito/hindama-backend/${HINDAMA_REF}/deploy/backend"
DIR=/opt/hindama

if [[ ! "$HINDAMA_REF" =~ ^[0-9a-f]{40}$ ]]; then
  echo "HINDAMA_REF debe ser el SHA completo de un commit" >&2
  exit 1
fi

# ---------------------------------------------------------------- Docker and Compose
dnf install -y docker
systemctl enable --now docker

plugin=/usr/local/lib/docker/cli-plugins/docker-compose
if [[ ! -x "$plugin" ]] || ! docker compose version | grep -q "${COMPOSE_VERSION#v}"; then
  mkdir -p "$(dirname "$plugin")"
  curl -fsSL -o /tmp/docker-compose \
    "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-aarch64"
  echo "${COMPOSE_SHA256}  /tmp/docker-compose" | sha256sum -c -
  install -m 0755 /tmp/docker-compose "$plugin"
  rm -f /tmp/docker-compose
fi

# ---------------------------------------------------------------- swap (architecture 3.1)
if [[ ! -f /swapfile ]]; then
  dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
  chmod 600 /swapfile
  mkswap /swapfile
  echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi
swapon --show | grep -q /swapfile || swapon /swapfile

# ---------------------------------------------------------------- files
install -d -m 0755 "$DIR"
# RDS certificate authorities of the region: asyncpg verifies the server with them.
curl -fsSL -o "$DIR/rds-ca.pem" \
  https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem
chmod 0644 "$DIR/rds-ca.pem"
for file in compose.yaml Caddyfile load-env.sh init-rds.sh rds-roles.sql hindama-backend.service; do
  curl -fsSL -o "$DIR/$file" "$RAW/$file"
done
chmod 0700 "$DIR/load-env.sh" "$DIR/init-rds.sh"
chmod 0644 "$DIR/compose.yaml" "$DIR/Caddyfile" "$DIR/rds-roles.sql"
install -m 0644 "$DIR/hindama-backend.service" /etc/systemd/system/hindama-backend.service

# ---------------------------------------------------------------- start
systemctl daemon-reload
systemctl enable hindama-backend
systemctl restart hindama-backend
echo "backend iniciado con deploy/backend de ${HINDAMA_REF}"
