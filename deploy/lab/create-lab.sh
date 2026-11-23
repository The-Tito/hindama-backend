#!/usr/bin/env bash
# Creates the lab's EC2 ONCE (it already exists: for the demo it is only started, with demo.sh).
# Use it to rebuild the lab in another account or after deleting it.
#
#   LAB_REF=<full SHA of a commit with tests/lab/app.py> deploy/lab/create-lab.sh
#
# Creates hindama-sg-lab (port 80 only from the backend's Elastic IP), the role hindama-lab-ec2
# (Session Manager only) and a t4g.micro without key pair, with IMDSv2 and an encrypted disk.
# Everything is found by its Name tag; the network must exist (PROCEDIMIENTO.md §3 and §6.2).
set -euo pipefail

export AWS_PROFILE="${AWS_PROFILE:-hindama}" AWS_REGION="${AWS_REGION:-us-east-1}"
LAB_REF="${LAB_REF:?Indica LAB_REF: el SHA completo del commit cuyo laboratorio se instala}"
[[ "$LAB_REF" =~ ^[0-9a-f]{40}$ ]] || { echo "LAB_REF debe ser un SHA completo" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
IAM="$HERE/../backend/iam"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

subnet="$(aws ec2 describe-subnets --filters Name=tag:Name,Values=hindama-publica-a \
  --query 'Subnets[0].SubnetId' --output text)"
vpc="$(aws ec2 describe-subnets --subnet-ids "$subnet" --query 'Subnets[0].VpcId' --output text)"
eip="$(aws ec2 describe-addresses --filters Name=tag:Name,Values=hindama-backend-eip \
  --query 'Addresses[0].PublicIp' --output text)"
echo "Subred ${subnet} en ${vpc}; IP del backend ${eip}"

sg="$(aws ec2 create-security-group --vpc-id "$vpc" --group-name hindama-sg-lab \
  --description "Laboratorio: 80 solo desde la IP elastica del backend" \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=hindama-sg-lab},{Key=Project,Value=hindama}]' \
  --query GroupId --output text)"
aws ec2 authorize-security-group-ingress --group-id "$sg" --ip-permissions \
  "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=${eip}/32,Description=backend}]" >/dev/null

# The lab's role: only the Session Manager statement of the backend's policy.
python3 - "$IAM/ec2-backend.json" "$work/policy-lab.json" <<'PY'
import json, sys
statements = json.load(open(sys.argv[1]))["Statement"]
session = [s for s in statements if s.get("Sid") == "SessionManagerYRunCommand"]
json.dump({"Version": "2012-10-17", "Statement": session}, open(sys.argv[2], "w"))
PY
aws iam create-role --role-name hindama-lab-ec2 --assume-role-policy-document "file://$IAM/ec2-trust.json" \
  --description "Laboratorio: solo Session Manager" --tags Key=Project,Value=hindama >/dev/null
aws iam put-role-policy --role-name hindama-lab-ec2 --policy-name hindama-lab-session \
  --policy-document "file://$work/policy-lab.json"
aws iam create-instance-profile --instance-profile-name hindama-lab-ec2 >/dev/null
aws iam add-role-to-instance-profile --instance-profile-name hindama-lab-ec2 --role-name hindama-lab-ec2
aws iam wait instance-profile-exists --instance-profile-name hindama-lab-ec2
sleep 10  # IAM is eventually consistent: EC2 rejects a profile that is only seconds old

sed "s/LAB_REF_PLACEHOLDER/${LAB_REF}/" "$HERE/lab-user-data.sh" >"$work/user-data.sh"
ami="$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64 \
  --query Parameter.Value --output text)"
lab="$(aws ec2 run-instances --image-id "$ami" --instance-type t4g.micro \
  --network-interfaces "DeviceIndex=0,SubnetId=${subnet},Groups=${sg},AssociatePublicIpAddress=true" \
  --iam-instance-profile Name=hindama-lab-ec2 \
  --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=8,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}' \
  --credit-specification CpuCredits=standard \
  --user-data "file://$work/user-data.sh" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=hindama-lab},{Key=Project,Value=hindama}]' \
  --query 'Instances[0].InstanceId' --output text)"
aws ec2 wait instance-running --instance-ids "$lab"
echo "Laboratorio ${lab}, SG ${sg}. Publica su registro A con: deploy/lab/demo.sh start"
