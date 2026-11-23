#!/usr/bin/env bash
# Runs the shell script read from stdin on an EC2 (by its Name tag) through SSM Run Command.
# The command's stdout goes to stdout and its stderr to stderr; fails if the command failed.
#
#   echo 'sudo systemctl status hindama-backend' | deploy/lab/ssm-run.sh hindama-backend
set -euo pipefail

export AWS_PROFILE="${AWS_PROFILE:-hindama}" AWS_REGION="${AWS_REGION:-us-east-1}"
NAME="${1:-hindama-backend}"

instance="$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=${NAME}" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].InstanceId' --output text)"
if [[ -z "$instance" || "$instance" == *[[:space:]]* ]]; then
  echo "Se esperaba exactamente una instancia encendida con Name=${NAME} y hay: '${instance}'" >&2
  exit 1
fi

script="$(cat)"
params="$(python3 -c 'import json, sys
print(json.dumps({"commands": [sys.argv[1]], "executionTimeout": ["900"]}))' "$script")"
id="$(aws ssm send-command --instance-ids "$instance" --document-name AWS-RunShellScript \
  --parameters "$params" --timeout-seconds 600 --query Command.CommandId --output text)"

status=Pending
for _ in $(seq 1 180); do
  status="$(aws ssm get-command-invocation --command-id "$id" --instance-id "$instance" \
    --query Status --output text 2>/dev/null || echo Pending)"
  case "$status" in Pending | InProgress | Delayed) sleep 5 ;; *) break ;; esac
done

aws ssm get-command-invocation --command-id "$id" --instance-id "$instance" \
  --query StandardOutputContent --output text
aws ssm get-command-invocation --command-id "$id" --instance-id "$instance" \
  --query StandardErrorContent --output text >&2
[[ "$status" == "Success" ]] || { echo "[estado: ${status}]" >&2; exit 1; }
