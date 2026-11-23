"""DNS records of the demo zone in Cloudflare (the lab's A record and the verification TXTs).

The token is read from SSM (/hindama/ops/cloudflare-dns-token) and never printed.

    python3 deploy/lab/cfdns.py list
    python3 deploy/lab/cfdns.py upsert TYPE NAME CONTENT
    python3 deploy/lab/cfdns.py delete TYPE NAME [CONTENT]

Only the standard library: it runs without the project's environment.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

ZONE = os.environ.get("HINDAMA_DNS_ZONE", "asolo.tech")
TOKEN_PARAMETER = os.environ.get("HINDAMA_DNS_TOKEN_PARAMETER", "/hindama/ops/cloudflare-dns-token")
API = "https://api.cloudflare.com/client/v4"


def read_token() -> str:
    result = subprocess.run(
        ["aws", "ssm", "get-parameter", "--name", TOKEN_PARAMETER, "--with-decryption",
         "--query", "Parameter.Value", "--output", "text"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    return result.stdout.strip()


def cloudflare(token: str, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    request = urllib.request.Request(  # fixed Cloudflare URL, never user input
        API + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        return json.load(error)


def same_content(record: dict[str, Any], content: str | None) -> bool:
    return content is None or record["content"].strip('"') == content


def main(args: list[str]) -> None:
    if not args or args[0] not in {"list", "upsert", "delete"}:
        sys.exit(__doc__)
    token = read_token()
    zone_id = cloudflare(token, "GET", f"/zones?name={ZONE}")["result"][0]["id"]
    records = cloudflare(token, "GET", f"/zones/{zone_id}/dns_records?per_page=100")["result"]
    command = args[0]

    if command == "list":
        for r in records:
            proxy = "proxy" if r.get("proxied") else "solo DNS"
            print(r["type"], r["name"], r["content"], proxy, r["ttl"])

    elif command == "upsert":
        kind, name, content = args[1:4]
        # An A record is replaced; TXT records coexist, so only an identical one is reused.
        same = [
            r for r in records
            if r["type"] == kind and r["name"] == name
            and (kind != "TXT" or same_content(r, content))
        ]  # fmt: skip
        body = {"type": kind, "name": name, "content": content, "ttl": 60, "proxied": False,
                "comment": "hindama"}  # fmt: skip
        path = f"/zones/{zone_id}/dns_records"
        response = (
            cloudflare(token, "PUT", f"{path}/{same[0]['id']}", body)
            if same
            else cloudflare(token, "POST", path, body)
        )
        outcome = (
            ("actualizado" if same else "creado") if response["success"] else response["errors"]
        )
        print(outcome, kind, name, content)

    else:
        kind, name = args[1:3]
        wanted = args[3] if len(args) > 3 else None
        matching = [
            r
            for r in records
            if r["type"] == kind and r["name"] == name and same_content(r, wanted)
        ]
        if not matching:
            print("no había", kind, name)
        for r in matching:
            response = cloudflare(token, "DELETE", f"/zones/{zone_id}/dns_records/{r['id']}")
            print("borrado" if response["success"] else "falló", kind, name, r["content"])


if __name__ == "__main__":
    main(sys.argv[1:])
