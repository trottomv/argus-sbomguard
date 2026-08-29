#!/usr/bin/env python3
"""Create an Argus API key and print it to stdout.

Usage: python scripts/create_api_key.py [label]

Used by .github/workflows/api-fuzzytest.yml to mint a key for the Schemathesis
run and handy for local automation. Database/settings come from the environment
(POSTGRES_*, RABBITMQ_*, ...), exactly like the app itself. The key belongs to
the admin user (config.admin_email, seeded on demand) and never expires. The
raw key is only printed once — store it, you cannot read it back.
"""

import asyncio
import sys
from pathlib import Path

# Make the app package importable regardless of the working directory the script
# is invoked from (e.g. the repo root), not just from inside app/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from database import async_session_factory
from services.auth import create_api_key, seed_admin_user


async def main() -> None:
    label = sys.argv[1] if len(sys.argv) > 1 else "cli"
    async with async_session_factory() as db:
        user = await seed_admin_user(db)
        _, raw = await create_api_key(db, user.id, label=label)
        await db.commit()
        print(raw)


if __name__ == "__main__":
    asyncio.run(main())
