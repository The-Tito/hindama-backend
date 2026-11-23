#!/usr/bin/env bash
# Turns the demo deployment on and off: RDS, the backend and lab EC2s, and the lab's A record.
#
#   deploy/lab/demo.sh status          states of everything and the current A record
#   deploy/lab/demo.sh start           RDS first, then both EC2s, then the A record
#   deploy/lab/demo.sh ca FILE         saves the root of the backend's Caddy CA (public certificate)
#   deploy/lab/demo.sh tunnel          opens the Session Manager tunnel to the backend's 8443
#   deploy/lab/demo.sh stop            deletes the A record, stops both EC2s and RDS
#
# Resources are found by their Name tag and identifier, never by fixed IDs (PROCEDIMIENTO.md §9).
set -euo pipefail

export AWS_PROFILE="${AWS_PROFILE:-hindama}" AWS_REGION="${AWS_REGION:-us-east-1}"
DB="${HINDAMA_DB_ID:-hindama-db}"
BACKEND="${HINDAMA_BACKEND_NAME:-hindama-backend}"
LAB="${HINDAMA_LAB_NAME:-hindama-lab}"
LAB_HOST="${HINDAMA_LAB_HOST:-lab.asolo.tech}"
HERE="$(cd "$(dirname "$0")" && pwd)"

instance_id() {
  local ids
  ids="$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$1" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text)"
  if [[ -z "$ids" || "$ids" == *[[:space:]]* ]]; then
    echo "Se esperaba exactamente una instancia con Name=$1 y hay: '${ids}'" >&2
    exit 1
  fi
  echo "$ids"
}

instance_field() {  # instance id, JMESPath field of the instance
  aws ec2 describe-instances --instance-ids "$1" --query "Reservations[0].Instances[0].$2" --output text
}

db_status() {
  aws rds describe-db-instances --db-instance-identifier "$DB" \
    --query 'DBInstances[0].DBInstanceStatus' --output text
}

cmd_status() {
  echo "RDS ${DB}: $(db_status)"
  for name in "$BACKEND" "$LAB"; do
    local id
    id="$(instance_id "$name")"
    echo "EC2 ${name} (${id}): $(instance_field "$id" State.Name), IP pública $(instance_field "$id" PublicIpAddress)"
  done
  echo "Registros de ${LAB_HOST}:"
  python3 "$HERE/cfdns.py" list | grep -F " ${LAB_HOST} " || echo "  (ninguno)"
}

cmd_start() {
  local backend lab status lab_ip
  backend="$(instance_id "$BACKEND")"
  lab="$(instance_id "$LAB")"

  # The lab does not depend on anything: it boots while RDS starts.
  aws ec2 start-instances --instance-ids "$lab" --query 'StartingInstances[0].CurrentState.Name' --output text

  status="$(db_status)"
  if [[ "$status" == "stopped" ]]; then
    aws rds start-db-instance --db-instance-identifier "$DB" --query DBInstance.DBInstanceStatus --output text
  fi
  echo "Esperando a que RDS esté disponible (suele tardar de 5 a 10 minutos)…"
  aws rds wait db-instance-available --db-instance-identifier "$DB"

  # The backend runs its migrations at boot, so it starts only once the database answers.
  aws ec2 start-instances --instance-ids "$backend" --query 'StartingInstances[0].CurrentState.Name' --output text
  aws ec2 wait instance-running --instance-ids "$lab" "$backend"

  # The lab has no Elastic IP: its public IP changes on every start.
  lab_ip="$(instance_field "$lab" PublicIpAddress)"
  python3 "$HERE/cfdns.py" upsert A "$LAB_HOST" "$lab_ip"
  echo "Listo. El backend tarda 1 o 2 minutos más en levantar sus contenedores."
  echo "Siguiente: '$0 ca <archivo>' (una vez) y '$0 tunnel' en otra terminal."
}

cmd_stop() {
  local backend lab status
  backend="$(instance_id "$BACKEND")"
  lab="$(instance_id "$LAB")"
  # First the A record: a name pointing at a released IP could end up at someone else's machine.
  python3 "$HERE/cfdns.py" delete A "$LAB_HOST"
  aws ec2 stop-instances --instance-ids "$backend" "$lab" --query 'StoppingInstances[].CurrentState.Name' --output text
  status="$(db_status)"
  if [[ "$status" == "available" ]]; then
    aws rds stop-db-instance --db-instance-identifier "$DB" --query DBInstance.DBInstanceStatus --output text
  else
    echo "RDS está en '${status}': no se detuvo. Vuelve a correr 'stop' cuando esté 'available'." >&2
  fi
  aws ec2 wait instance-stopped --instance-ids "$backend" "$lab"
  echo "Apagado. AWS vuelve a encender RDS sola a los 7 días: detenla otra vez si no se usa."
}

cmd_ca() {
  local file="${1:?Uso: $0 ca ARCHIVO}"
  # The root lives in the caddy-data volume; it is a public certificate, not a secret.
  echo 'cd /opt/hindama && docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt' \
    | "$HERE/ssm-run.sh" "$BACKEND" >"$file"
  openssl x509 -in "$file" -noout -subject -fingerprint -sha256
}

cmd_tunnel() {
  local backend private_ip
  backend="$(instance_id "$BACKEND")"
  private_ip="$(instance_field "$backend" PrivateIpAddress)"
  echo "Túnel: 127.0.0.1:8443 → ${BACKEND}:8443. Se cierra solo por inactividad; Ctrl+C para cerrarlo."
  exec aws ssm start-session --target "$backend" --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --parameters "{\"host\":[\"${private_ip}\"],\"portNumber\":[\"8443\"],\"localPortNumber\":[\"8443\"]}"
}

case "${1:-}" in
  status) cmd_status ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  ca) cmd_ca "${2:-}" ;;
  tunnel) cmd_tunnel ;;
  *) echo "Uso: $0 status|start|stop|ca ARCHIVO|tunnel" >&2; exit 2 ;;
esac
