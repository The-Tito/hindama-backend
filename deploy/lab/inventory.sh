#!/usr/bin/env bash
# Lists, in every region, what costs money even when idle: EC2 (running or stopped), EBS volumes,
# Elastic IPs, NAT gateways and RDS. Run it after demo.sh stop to confirm nothing was left behind.
set -uo pipefail  # no -e: a region that refuses a call is reported, not fatal

export AWS_PROFILE="${AWS_PROFILE:-hindama}"
O=(--cli-connect-timeout 10 --cli-read-timeout 20)
aws sts get-caller-identity "${O[@]}" --query Arn --output text || exit 1
for r in $(aws ec2 describe-regions "${O[@]}" --region us-east-1 --query 'Regions[].RegionName' --output text); do
  i=$(aws ec2 describe-instances "${O[@]}" --region "$r" --filters Name=instance-state-name,Values=pending,running,stopping,stopped --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name,Tags[?Key==`Name`]|[0].Value]' --output text 2>&1)
  v=$(aws ec2 describe-volumes "${O[@]}" --region "$r" --query 'Volumes[].[VolumeId,Size,State]' --output text 2>&1)
  e=$(aws ec2 describe-addresses "${O[@]}" --region "$r" --query 'Addresses[].[PublicIp,InstanceId]' --output text 2>&1)
  n=$(aws ec2 describe-nat-gateways "${O[@]}" --region "$r" --filter Name=state,Values=available --query 'NatGateways[].NatGatewayId' --output text 2>&1)
  d=$(aws rds describe-db-instances "${O[@]}" --region "$r" --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceStatus]' --output text 2>&1)
  if [ -n "$i$v$e$n$d" ]; then
    echo "== $r"
    [ -n "$i" ] && echo "EC2: $i"
    [ -n "$v" ] && echo "EBS: $v"
    [ -n "$e" ] && echo "IP elásticas: $e"
    [ -n "$n" ] && echo "NAT: $n"
    [ -n "$d" ] && echo "RDS: $d"
  fi
done
echo "(fin del inventario)"
