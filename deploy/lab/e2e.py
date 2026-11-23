"""End-to-end run against Hindama in AWS, through the Session Manager tunnel (127.0.0.1:8443).

For each project: creates it on the lab, imports its contract, sets the policies, the three
identities and their resources, verifies it by DNS (TXT in Cloudflare with cfdns.py), launches
every available module and prints the findings. With N > 1 the runs go at the same time (the
load test of the architecture, RNF-04). Ends with the API's response times (RNF-01).

    PYTHONPATH=. uv run python deploy/lab/e2e.py [N]   # from hindama-backend, tunnel open

Inputs, all outside the repository (PROCEDIMIENTO.md §9):
    HINDAMA_E2E_TOKEN_FILE  file (0600) with the analyst's access token; never printed
    HINDAMA_E2E_CA_FILE     root of the backend's Caddy CA (demo.sh ca FILE)
    HINDAMA_LAB_URL         base URL of the lab (default http://lab.asolo.tech)
    HINDAMA_E2E_TIMINGS     optional: JSON file where the measured times are saved
"""

import json
import os
import ssl
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
from tests.lab.app import ANA_PASSWORD, BETO_TOKEN, RAIZ_TOKEN

HERE = Path(__file__).parent
LAB = os.environ.get("HINDAMA_LAB_URL", "http://lab.asolo.tech")
API = "https://127.0.0.1:8443"
SNI = {"sni_hostname": "backend.internal"}
POLICIES = {
    "POST /auth/login": ("public", None),
    "GET /orders": ("authenticated", None),
    "GET /orders/{order_id}": ("owner_only", "owner"),
    "DELETE /orders/{order_id}": ("owner_only", "owner"),
    "GET /invoices/{invoice_id}": ("owner_only", "owner"),
    "GET /accounts/{account_id}/statement": ("owner_or_admin", "owner"),
    "GET /reports": ("authenticated", None),
    "GET /admin/users": ("admin_only", None),
    "GET /admin/audit": ("admin_only", None),
    "DELETE /admin/users/{user_id}": ("admin_only", None),
}
RESOURCES = {
    "ana": [("orders", "ord-ana-1"), ("invoices", "inv-ana-1"), ("accounts", "acc-ana")],
    "beto": [("orders", "ord-beto-1"), ("invoices", "inv-beto-1"), ("accounts", "acc-beto")],
}
TIMINGS: list[tuple[str, float, int]] = []  # (operation, seconds, status): RNF-01


def required_file(variable: str) -> Path:
    value = os.environ.get(variable)
    if not value or not Path(value).is_file():
        sys.exit(f"Falta {variable}: ruta a un archivo existente (PROCEDIMIENTO.md §9).")
    return Path(value)


TOKEN = required_file("HINDAMA_E2E_TOKEN_FILE").read_text().strip()
CA = required_file("HINDAMA_E2E_CA_FILE")


def client() -> httpx.Client:
    context = ssl.create_default_context(cafile=str(CA))
    return httpx.Client(
        base_url=API,
        verify=context,
        headers={"Host": "backend.internal", "Authorization": f"Bearer {TOKEN}"},
        timeout=30,
    )


def call(http: httpx.Client, method: str, path: str, label: str, **kwargs: Any) -> Any:
    for _ in range(6):
        start = time.perf_counter()
        response = http.request(method, path, extensions=SNI, **kwargs)
        TIMINGS.append((label, time.perf_counter() - start, response.status_code))
        if response.status_code != 429:  # RNF-09: 100 per minute per user
            break
        time.sleep(int(response.headers.get("retry-after", "10")))
    if response.status_code >= 300:
        sys.exit(f"{method} {path} -> {response.status_code}: {response.text[:400]}")
    return response.json() if response.content else None


def dns(*args: str) -> None:
    subprocess.run([sys.executable, str(HERE / "cfdns.py"), *args], check=True)


def prepare(http: httpx.Client, number: int) -> tuple[str, dict[str, Any]]:
    project = call(
        http, "POST", "/projects", "createProject",
        json={"name": f"Laboratorio AWS {number}", "base_url": LAB},
    )  # fmt: skip
    p = f"/projects/{project['id']}"
    call(
        http,
        "POST",
        f"{p}/contracts",
        "importContract",
        files={"url": (None, f"{LAB}/openapi.json")},
    )
    ops = call(http, "GET", f"{p}/operations", "listOperations", params={"page_size": 100})
    operations = {f"{o['method']} {o['path']}": o["id"] for o in ops["items"]}
    for key, (policy, owner_field) in POLICIES.items():
        call(
            http, "PATCH", f"{p}/operations/{operations[key]}", "updateOperation",
            json={"policy": policy, "owner_field": owner_field},
        )  # fmt: skip
    login = operations["POST /auth/login"]
    bodies: list[dict[str, Any]] = [
        {"name": "ana", "role": "user", "auth_type": "login", "login_operation_id": login,
         "credential": {"username": "ana", "password": ANA_PASSWORD}},
        {"name": "beto", "role": "user", "auth_type": "bearer",
         "credential": {"token": BETO_TOKEN}},
        {"name": "raiz", "role": "admin", "auth_type": "bearer",
         "credential": {"token": RAIZ_TOKEN}},
    ]  # fmt: skip
    identities = {
        b["name"]: call(http, "POST", f"{p}/identities", "createIdentity", json=b)["id"]
        for b in bodies
    }
    for name, owned in RESOURCES.items():
        for kind, value in owned:
            call(
                http, "POST", f"{p}/resources", "createResource",
                json={"identity_id": identities[name], "resource_type": kind, "value": value},
            )  # fmt: skip
    return project["id"], call(http, "GET", f"{p}/verification", "getVerification")


def verify(http: httpx.Client, pid: str) -> None:
    # A new TXT can take a while to be visible to the backend's resolver (negative cache).
    for _ in range(18):
        response = http.post(
            f"/projects/{pid}/verification", json={"method": "dns"}, extensions=SNI
        )
        if response.status_code == 200 and response.json().get("status") == "verified":
            return
        time.sleep(10)
    sys.exit(f"verificación fallida: {response.status_code} {response.text[:300]}")


def launch(http: httpx.Client, pid: str) -> str:
    project = call(http, "GET", f"/projects/{pid}", "getProject")
    available = [m for m in project["modules"] if m["available"]]
    modules = [m["module"] for m in available]
    risky = any(m.get("risk") == "high" for m in available)
    body = {"modules": modules, "confirm_risk": True} if risky else {"modules": modules}
    run = call(http, "POST", f"/projects/{pid}/runs", "createRun", json=body)
    print(f"  ejecución {run['number']} con {modules}")
    return str(run["id"])


def wait(pid: str, rid: str) -> dict[str, Any]:
    started = time.perf_counter()
    with client() as http:
        while True:
            run: dict[str, Any] = call(http, "GET", f"/projects/{pid}/runs/{rid}", "getRun")
            if run["status"] not in ("queued", "running"):
                run["_seconds"] = time.perf_counter() - started
                return run
            time.sleep(5)


def report(http: httpx.Client, pid: str, run: dict[str, Any]) -> None:
    pr = run["progress"]
    print(
        f"  estado {run['status']} ({run['end_reason']}) en {run['_seconds']:.0f} s; "
        f"{pr['requests_sent']} peticiones; {pr['cells_evaluated']}/{pr['cells_planned']} celdas"
    )
    print("  hallazgos por severidad:", pr["findings_by_severity"])
    found = call(
        http, "GET", f"/projects/{pid}/findings", "listFindings", params={"page_size": 100}
    )
    for f in sorted(found["items"], key=lambda x: (x["severity"], x["finding_type"])):
        print(f"    [{f['severity']}] {f['finding_type']}: {f['title']}")


def main() -> None:
    projects = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    with client() as http:
        me = call(http, "GET", "/me", "getMe")
        if me["terms"]["acceptance_required"]:
            version = me["terms"]["current_version"]
            call(http, "POST", "/me/terms", "acceptTerms", json={"version": version})
        prepared = []
        for n in range(1, projects + 1):
            pid, verification = prepare(http, n)
            dns("upsert", "TXT", verification["dns"]["name"], verification["dns"]["value"])
            prepared.append(pid)
        print(f"{len(prepared)} proyecto(s) preparado(s); verificando por DNS…")
        for pid in prepared:
            verify(http, pid)
        runs = [(pid, launch(http, pid)) for pid in prepared]
        with ThreadPoolExecutor(max_workers=len(runs)) as pool:
            finished = list(pool.map(lambda r: wait(*r), runs))
        for (pid, _), run in zip(runs, finished, strict=True):
            print(f"proyecto {pid}:")
            report(http, pid, run)

    by_op: dict[str, list[float]] = {}
    for label, seconds, _ in TIMINGS:
        by_op.setdefault(label, []).append(seconds)
    every = sorted(s for _, s, _ in TIMINGS)
    p95 = every[int(0.95 * (len(every) - 1))]
    print(
        f"\nRNF-01: {len(every)} peticiones a la API; p95 = {p95 * 1000:.0f} ms; "
        f"máx = {every[-1] * 1000:.0f} ms (incluye el túnel)"
    )
    for label, values in sorted(by_op.items()):
        print(f"  {label}: n={len(values)} mediana={statistics.median(values) * 1000:.0f} ms")
    if timings := os.environ.get("HINDAMA_E2E_TIMINGS"):
        Path(timings).write_text(json.dumps(TIMINGS))


if __name__ == "__main__":
    main()
