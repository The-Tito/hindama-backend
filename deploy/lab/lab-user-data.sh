#!/usr/bin/env bash
# User data of the lab's EC2: the catalog lab (tests/lab/app.py) in VULNERABLE mode on port 80,
# for the end-to-end run, the load test and the demo. create-lab.sh replaces LAB_REF_PLACEHOLDER
# with the full SHA of the commit whose lab is installed (catalogo-laboratorio.md).
# The container runs unprivileged, read-only, without capabilities and with 512 MB.
set -euo pipefail
REF=LAB_REF_PLACEHOLDER
if [[ ! "$REF" =~ ^[0-9a-f]{40}$ ]]; then
  echo "REF debe ser el SHA completo de un commit" >&2
  exit 1
fi

dnf install -y docker
systemctl enable --now docker
install -d -m 0755 /opt/lab/tests/lab
for f in tests/__init__.py tests/lab/__init__.py tests/lab/app.py; do
  curl -fsSL -o "/opt/lab/$f" "https://raw.githubusercontent.com/The-Tito/hindama-backend/${REF}/$f"
done
cat >/opt/lab/run.py <<'PY'
import uvicorn
from tests.lab.app import Mode, build_lab
uvicorn.run(build_lab(Mode.VULNERABLE), host="0.0.0.0", port=8000, log_level="warning")
PY
chmod -R a+rX /opt/lab
docker run -d --name lab --restart unless-stopped -p 80:8000 \
  --user 65534:65534 --read-only --tmpfs /tmp:exec,size=256m --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 512m \
  -e HOME=/tmp -v /opt/lab:/app:ro -w /app python:3.12-slim \
  sh -c "pip install --quiet --no-cache-dir --target /tmp/deps fastapi==0.162.0 uvicorn==0.54.0 pydantic==2.14.2 starlette==1.10.0 && PYTHONPATH=/tmp/deps:/app exec python run.py"
