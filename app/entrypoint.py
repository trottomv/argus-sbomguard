#!/usr/bin/env python3
"""Container entrypoint: run DB migrations for the API, then exec the command."""

import logging
import os
import sys
import time

import alembic.command as alembic_command
import alembic.config as alembic_config

MAX_RETRIES = 10
RETRY_DELAY_SECONDS = 2

logger = logging.getLogger(__name__)


def _run_migrations() -> None:
    config = alembic_config.Config("/app/alembic.ini")
    logger.info("Running database migrations...")
    for attempt in range(MAX_RETRIES + 1):
        try:
            alembic_command.upgrade(config, "head")
            logger.info("Migrations complete.")
            return
        except Exception as exc:
            if attempt == MAX_RETRIES:
                logger.error(
                    "Migration failed after %d attempts, continuing anyway: %s",
                    MAX_RETRIES,
                    exc,
                )
                return
            logger.warning(
                "Migration failed, retrying in %ds (%d/%d): %s",
                RETRY_DELAY_SECONDS,
                attempt + 1,
                MAX_RETRIES,
                exc,
            )
            time.sleep(RETRY_DELAY_SECONDS)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    args = sys.argv[1:]
    if args and args[0] == "uvicorn":
        _run_migrations()
    logger.info("Starting application...")
    if args:
        os.execvp(args[0], args)  # nosec B606


if __name__ == "__main__":
    main()
