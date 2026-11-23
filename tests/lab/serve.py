"""Serves the lab on its own, for manual tests through a public tunnel (postman/README.md).

    uv run python -m tests.lab.serve --mode vulnerable

The scanner never reaches loopback (SSRF guard), so the lab is exposed with a tunnel and the
project's base URL is the tunnel's HTTPS URL. On top of the lab:

- `/.well-known/hindama-verificacion.txt` answers the content of `--verification-file`, read on
  every request: paste the project's code there and verify by file, without restarting.
- The mode is fixed at start. To "fix" the lab between two runs (RF-68), restart it with
  `--mode secure`; the tunnel keeps its URL.

The lab's own contract stays at `/openapi.json`, so the analyst can import it by URL.
"""

import argparse
from pathlib import Path

import uvicorn
from fastapi.responses import PlainTextResponse

from tests.lab.app import Mode, build_lab

DEFAULT_VERIFICATION_FILE = Path(__file__).parent / ".verificacion.txt"


def main() -> None:
    parser = argparse.ArgumentParser(description="Laboratorio de Hindama para pruebas manuales")
    parser.add_argument("--mode", choices=[m.value for m in Mode], default=Mode.VULNERABLE.value)
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--verification-file", type=Path, default=DEFAULT_VERIFICATION_FILE)
    args = parser.parse_args()
    verification_file: Path = args.verification_file

    lab = build_lab(Mode(args.mode))

    def verification() -> PlainTextResponse:  # sync: FastAPI runs it in a thread
        try:
            content = verification_file.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return PlainTextResponse("", status_code=404)
        return PlainTextResponse(content)

    lab.add_api_route(
        "/.well-known/hindama-verificacion.txt", verification, include_in_schema=False
    )
    print(f"Laboratorio en modo {args.mode}; código de verificación en {verification_file}")  # noqa: T201
    # Loopback only: the tunnel is the one public door.
    uvicorn.run(lab, host="127.0.0.1", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
