"""The real API for Schemathesis (ADR-016, technical test PT-03). Used by `run.sh`.

Real PostgreSQL (`HINDAMA_TEST_DATABASE_URL`, the API role with RLS); fake Cognito, DNS and run
queue from the tests. Once the analyst has accepted the terms, writes their access token to the
token file (the signal that the API is ready) and serves until stopped. An administrator's token
goes to `<token file>.admin`, for the operations of `/admin/*` (a second pass of `run.sh`).

`--cleanup` deletes that analyst and the administrator, and with them everything Schemathesis
created, so the integration tests find `hindama_test` clean. It is a separate step because uvicorn
re-raises SIGTERM after shutting down, which ends the process before any `finally`. The server also
runs it on start, in case a previous run was killed.
"""

import asyncio
import os
import sys
from pathlib import Path

import httpx
import uvicorn
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import create_async_engine

from hindama.api import run_stream
from hindama.main import create_app
from hindama.models import User
from tests.conftest import make_settings
from tests.dns import FakeResolver
from tests.events import MemoryRunEvents
from tests.ownership import ScriptedChecker
from tests.queue import MemoryRunQueue
from tests.tokens import ADMIN_GROUP, FakeUserPool

# Its own analyst: never the default `sub` of the integration tests.
SUB = "0192e3a0-5c4e-7000-8000-000000005c4e"
ADMIN_SUB = "0192e3a0-5c4e-7000-8000-00000000ad31"
HOST = "127.0.0.1"
PORT = int(os.environ.get("HINDAMA_SCHEMATHESIS_PORT", "8765"))
TOKEN_FILE = Path(os.environ.get("HINDAMA_SCHEMATHESIS_TOKEN", ".schemathesis-token"))
ADMIN_TOKEN_FILE = TOKEN_FILE.with_name(TOKEN_FILE.name + ".admin")


async def accept_terms(token: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(base_url=f"http://{HOST}:{PORT}", headers=headers) as client:
        me = (await client.get("/me")).raise_for_status().json()
        version = me["terms"]["current_version"]
        (await client.post("/me/terms", json={"version": version})).raise_for_status()


async def register(token: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(base_url=f"http://{HOST}:{PORT}", headers=headers) as client:
        (await client.get("/me")).raise_for_status()


async def delete_analyst() -> None:
    url = os.environ.get("HINDAMA_TEST_OWNER_DATABASE_URL")
    if not url:
        return
    engine = create_async_engine(url)
    try:
        async with engine.begin() as connection:
            await connection.execute(delete(User).where(User.cognito_sub.in_([SUB, ADMIN_SUB])))
    finally:
        await engine.dispose()


async def main() -> None:
    pool = FakeUserPool()
    app = create_app(
        make_settings(os.environ["HINDAMA_TEST_DATABASE_URL"]),
        verifier=pool.verifier(),
        profiles=pool.profile_client(),
        resolver=FakeResolver(),
        ownership_checker=ScriptedChecker(),  # never reaches the hosts Schemathesis invents
        run_queue=MemoryRunQueue(),  # runs are created, never executed: no scanner here
        run_events=MemoryRunEvents(),
    )
    # Without a scanner a run stays queued: its stream would wait for 15 minutes to close.
    run_stream.MAX_STREAM_SECONDS = 1.0
    token = pool.token(sub=SUB)
    server = uvicorn.Server(uvicorn.Config(app, host=HOST, port=PORT, log_level="warning"))
    # Same event loop for the setup requests and the server: the database connections of the app
    # belong to one loop (PT-03 found a 503 when the setup ran in another one).
    await delete_analyst()
    serving = asyncio.create_task(server.serve())
    while not server.started:
        if serving.done():
            await serving  # startup failed: raise its error
            return
        await asyncio.sleep(0.05)
    await accept_terms(token)
    pool.mfa.add(ADMIN_SUB)  # the panel requires the TOTP (RF-86)
    admin_token = pool.token(sub=ADMIN_SUB, groups=[ADMIN_GROUP])
    await register(admin_token)  # its first request leaves something in the audit log to list
    await asyncio.to_thread(ADMIN_TOKEN_FILE.write_text, admin_token)
    await asyncio.to_thread(TOKEN_FILE.write_text, token)  # last: the signal that all is ready
    await serving


if __name__ == "__main__":
    asyncio.run(delete_analyst() if "--cleanup" in sys.argv[1:] else main())
