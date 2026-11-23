"""`python -m hindama.scanner`: runs the worker until SIGTERM or SIGINT."""

import asyncio

from hindama.core.logging import configure_logging
from hindama.scanner.config import ScannerSettings
from hindama.scanner.worker import build_worker


def main() -> None:
    settings = ScannerSettings()  # required fields come from the environment
    configure_logging(settings.log_level, settings.log_format)
    asyncio.run(build_worker(settings).start())


if __name__ == "__main__":
    main()
