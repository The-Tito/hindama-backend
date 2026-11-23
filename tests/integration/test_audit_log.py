"""The audit log (CU-21; RF-81 to RF-84, RN-09; ADR-015).

What each sensitive action leaves, what an entry never holds (RF-83), and the administrator's
search with its filters (RF-84). The scanner's entries (`project_verification_lost` and the blocks
during a run) are checked in test_scanner.py; RN-09 in test_findings.py.
"""

from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.audit import actions, audit_entries, details_of
from tests.conftest import TEST_HASHER
from tests.dns import FakeResolver
from tests.integration.conftest import Analyst
from tests.integration.test_runs import start

IP = "X-Hindama-Client-IP"
BROWSER_IP = "203.0.113.25"
HOST = "api.ejemplo.com"
TOKEN = "s3cr3t-t0k3n-de-prueba-9f2a"


async def user_id(analyst: Analyst) -> str:
    me: dict[str, Any] = (await analyst.request("GET", "/me")).json()
    return str(me["id"])


@pytest.fixture
async def analyst(new_analyst: Any) -> Analyst:
    """An analyst whose browser IP the frontend reports from the first request."""
    analyst: Analyst = new_analyst()
    analyst.headers[IP] = BROWSER_IP
    await analyst.accept_terms()
    return analyst


# ------------------------------------------------------------------ what is audited (RF-81)


async def test_the_sensitive_actions_of_an_analyst(analyst: Analyst, owner: AsyncEngine) -> None:
    me = await user_id(analyst)
    project = await analyst.create()
    pid = project["id"]
    url = f"/projects/{pid}"
    verified = await analyst.request("POST", f"{url}/verification", json={"method": "dns"})
    assert verified.status_code == 200, verified.text
    identity = await analyst.request(
        "POST",
        f"{url}/identities",
        json={
            "name": "Usuario A",
            "role": "user",
            "auth_type": "bearer",
            "credential": {"token": TOKEN},
        },
    )
    assert identity.status_code == 201, identity.text
    identity_id = identity.json()["id"]
    assert (await analyst.request("DELETE", f"{url}/identities/{identity_id}")).status_code == 204
    launched = await analyst.request(
        "POST", f"{url}/runs", json={"modules": ["configuration"], "limits": {"concurrency": 1}}
    )
    assert launched.status_code == 202, launched.text
    first_run = launched.json()["id"]
    assert (await analyst.request("POST", f"{url}/runs/{first_run}/cancel")).status_code == 202
    rerun = await analyst.request("POST", f"{url}/runs/{first_run}/rerun", json={})
    assert rerun.status_code == 202, rerun.text
    second_run = rerun.json()["id"]
    assert (await analyst.request("POST", f"{url}/runs/{second_run}/cancel")).status_code == 202
    deleted = await analyst.request("DELETE", url, params={"confirmation": project["name"]})
    assert deleted.status_code == 204, deleted.text

    entries = await audit_entries(owner, user_id=me)

    assert actions(entries) == [
        "account_created",
        "project_created",
        "project_verified",
        "identity_created",
        "identity_deleted",
        "run_launched",
        "run_cancelled",
        "run_launched",
        "run_cancelled",
        "project_deleted",
    ]
    assert {str(entry.source_ip) for entry in entries} == {BROWSER_IP}  # RF-82
    project_entries = entries[1:]
    assert {str(entry.project_id) for entry in project_entries} == {pid}
    assert entries[0].project_id is None
    # The host's HMAC, never the host (RF-83): on every action about the project or a run.
    digest = TEST_HASHER.digest(HOST)
    with_host = [e for e in entries if e.host_hmac is not None]
    assert actions(with_host) == [
        "project_created",
        "project_verified",
        "run_launched",
        "run_cancelled",
        "run_launched",
        "run_cancelled",
        "project_deleted",
    ]
    assert {(bytes(e.host_hmac), e.hmac_version) for e in with_host} == {  # type: ignore[arg-type]
        (digest.value, digest.version)
    }
    assert details_of(entries, "project_verified") == [{"verification_method": "dns"}]
    assert details_of(entries, "identity_created") == [{"identity_id": identity_id}]
    assert details_of(entries, "identity_deleted") == [{"identity_id": identity_id}]
    limits = {"requests_per_second": 5, "concurrency": 1, "max_requests": 5000}
    first, second = details_of(entries, "run_launched")
    assert first["run_id"] == first_run
    assert first["modules"] == ["configuration"]
    assert {k: first["limits"][k] for k in limits} == limits
    assert "source_run_id" not in first
    assert second["source_run_id"] == first_run  # RF-71
    assert second["run_id"] == second_run
    assert details_of(entries, "run_cancelled") == [{"run_id": first_run}, {"run_id": second_run}]
    # No credential, anywhere (RN-11, RF-83).
    assert TOKEN not in repr([(e.details, e.action) for e in entries])


async def test_a_failed_action_leaves_no_entry(analyst: Analyst, owner: AsyncEngine) -> None:
    """The entry shares the action's transaction: a refused deletion is not audited."""
    project = await analyst.create()

    response = await analyst.request(
        "DELETE", f"/projects/{project['id']}", params={"confirmation": "otro nombre"}
    )

    assert response.status_code == 422
    assert actions(await audit_entries(owner, project_id=project["id"])) == ["project_created"]


async def test_a_repeated_cancel_is_audited_once(analyst: Analyst, owner: AsyncEngine) -> None:
    project = await analyst.create()
    url = f"/projects/{project['id']}"
    await analyst.request("POST", f"{url}/verification", json={"method": "dns"})
    run = (await analyst.request("POST", f"{url}/runs", json={"modules": ["configuration"]})).json()
    # A running run keeps accepting the cancel (the scanner stops it within 5 s).
    await start(owner, run["id"])
    for _ in range(2):
        response = await analyst.request("POST", f"{url}/runs/{run['id']}/cancel")
        assert response.status_code == 202, response.text

    entries = await audit_entries(owner, project_id=project["id"])
    assert actions(entries).count("run_cancelled") == 1


@pytest.mark.parametrize("given", ["no es una ip", "203.0.113.25, 10.0.0.1", "fe80::1%eth0", ""])
async def test_a_client_ip_that_is_not_an_address_is_not_kept(
    new_analyst: Any, owner: AsyncEngine, given: str
) -> None:
    analyst: Analyst = new_analyst()
    analyst.headers[IP] = given
    await analyst.accept_terms()

    (entry,) = await audit_entries(owner, user_id=await user_id(analyst))

    assert (entry.action, entry.source_ip) == ("account_created", None)


async def test_an_ipv6_client_is_kept_normalized(new_analyst: Any, owner: AsyncEngine) -> None:
    analyst: Analyst = new_analyst()
    analyst.headers[IP] = "2001:DB8:0:0::1"
    await analyst.accept_terms()

    (entry,) = await audit_entries(owner, user_id=await user_id(analyst))

    assert str(entry.source_ip) == "2001:db8::1"


# ------------------------------------------------------------------ blocked destinations (RF-81)


async def test_a_project_url_to_a_private_address_is_audited(
    analyst: Analyst, owner: AsyncEngine, resolver: FakeResolver
) -> None:
    """The request fails with 422, and the block is audited anyway (its own transaction)."""
    resolver.set("interna.ejemplo.com", "10.0.0.7")

    response = await analyst.request(
        "POST",
        "/projects",
        json={"name": "Interna", "base_url": "https://INTERNA.ejemplo.com:8443"},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "url.destination_not_allowed"
    (entry,) = [
        e
        for e in await audit_entries(owner, user_id=await user_id(analyst))
        if e.action == "destination_blocked"
    ]
    assert entry.project_id is None
    assert str(entry.source_ip) == BROWSER_IP
    assert entry.details == {"stage": "project_url", "block_reason": "address_not_allowed"}
    assert bytes(entry.host_hmac or b"") == TEST_HASHER.digest("interna.ejemplo.com").value


async def test_a_blocked_contract_download_is_audited(
    analyst: Analyst, owner: AsyncEngine, resolver: FakeResolver
) -> None:
    project = await analyst.create()
    resolver.set("docs.interna.test", "169.254.169.254")  # cloud metadata

    response = await analyst.request(
        "POST",
        f"/projects/{project['id']}/contracts",
        data={"url": "https://docs.interna.test/openapi.json"},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "contract.url_not_allowed"
    blocked = [
        e
        for e in await audit_entries(owner, project_id=project["id"])
        if e.action == "destination_blocked"
    ]
    assert [e.details for e in blocked] == [
        {"stage": "contract_import", "block_reason": "address_not_allowed"}
    ]
    assert bytes(blocked[0].host_hmac or b"") == TEST_HASHER.digest("docs.interna.test").value


async def test_an_unresolved_name_is_not_a_block(
    analyst: Analyst, owner: AsyncEngine, resolver: FakeResolver
) -> None:
    project = await analyst.create()
    resolver.unresolved.add("no-existe.ejemplo.com")

    await analyst.request(
        "POST",
        f"/projects/{project['id']}/contracts",
        data={"url": "https://no-existe.ejemplo.com/openapi.json"},
    )

    assert "destination_blocked" not in actions(
        await audit_entries(owner, project_id=project["id"])
    )
