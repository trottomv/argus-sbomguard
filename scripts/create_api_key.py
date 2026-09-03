#!/usr/bin/env python3
"""Create an Argus API key and print it to stdout.

Usage: python scripts/create_api_key.py [label] [--ttl-days N | --no-expiry]

Used by .github/workflows/api-fuzzytest.yml to mint a key for the Schemathesis
run and handy for local automation. Database/settings come from the environment
(POSTGRES_*, RABBITMQ_*, ...), exactly like the app itself. The key belongs to
the admin user (config.admin_email, seeded on demand) and expires after the
configured API_KEY_TTL_DAYS by default (forced rotation); use --no-expiry or
--ttl-days to override. The raw key is only printed once — store it, you cannot
read it back.
"""

import argparse
import asyncio
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Make the app package importable regardless of the working directory the script
# is invoked from (e.g. the repo root), not just from inside app/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from database import async_session_factory
from services.auth import api_key_default_expiry, create_api_key, seed_admin_user


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an Argus API key and print the raw key to stdout."
    )
    parser.add_argument("label", nargs="?", default="cli", help="key label")
    ttl = parser.add_mutually_exclusive_group()
    ttl.add_argument(
        "--ttl-days",
        type=int,
        metavar="N",
        help="expire the key after N days (overrides the configured default)",
    )
    ttl.add_argument(
        "--no-expiry",
        action="store_true",
        help="create a key that never expires (overrides the configured default)",
    )
    return parser.parse_args()


def _expiry(args: argparse.Namespace) -> datetime | None:
    if args.no_expiry:
        return None
    if args.ttl_days is not None:
        return datetime.now(UTC) + timedelta(days=args.ttl_days)
    return api_key_default_expiry()


async def main() -> None:
    args = _parse_args()
    async with async_session_factory() as db:
        user = await seed_admin_user(db)
        _, raw = await create_api_key(
            db, user.id, label=args.label, expires_at=_expiry(args)
        )
        await db.commit()
        print(raw)


if __name__ == "__main__":
    asyncio.run(main())
