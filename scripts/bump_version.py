#!/usr/bin/env python3
"""Propagate the version from app/VERSION.md to every file that mirrors it.

Usage: python3 scripts/bump_version.py

The full version lives in one place — app/VERSION.md. Edit that file, then run
this script to rewrite every other file that mirrors it:

- `.env.example` and the GHCR tag fallback in `docker-compose.remote.yml` get
  the `major.minor` tag, so remote deployments track the latest patch release
  in that series (the build workflow publishes both `x.y.z` and `x.y` tags).
- `docs/api/openapi.json` gets the full `x.y.z` version in `info.version`.

The previous full version is read from `docs/api/openapi.json`. The README
badge and the docs reference the latest release instead of a concrete version,
so they are not updated here.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "app" / "VERSION.md"
ENV_EXAMPLE = ROOT / ".env.example"
OPENAPI = ROOT / "docs" / "api" / "openapi.json"

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$")
_ENV_APP_VERSION_RE = re.compile(r"^APP_VERSION=.*$", re.MULTILINE)
_COMPOSE_APP_VERSION_RE = re.compile(r"\$\{APP_VERSION:-[^}]+\}")
_OPENAPI_VERSION_RE = re.compile(
    r'"title"\s*:\s*"[^"]*"\s*,\s*"version"\s*:\s*"([^"]+)"', re.DOTALL
)


def _major_minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


def _read_previous_version() -> str:
    match = _OPENAPI_VERSION_RE.search(OPENAPI.read_text())
    if not match:
        raise SystemExit(f"could not find info.version in {OPENAPI.name}")
    return match.group(1).strip()


def _replace(path: Path, pattern: re.Pattern[str], replacement: str) -> None:
    text = path.read_text()
    new_text, count = pattern.subn(replacement, text)
    if count == 0:
        print(f"warning: no match in {path.name}", file=sys.stderr)
        return
    path.write_text(new_text)
    print(f"{path.name}: {count} occurrence(s) updated")


def main() -> int:
    new_version = VERSION_FILE.read_text().strip()
    if not _VERSION_RE.fullmatch(new_version):
        print(f"invalid version in {VERSION_FILE.name}: {new_version!r}", file=sys.stderr)
        return 2

    old_version = _read_previous_version()
    if old_version == new_version:
        print(f"app/VERSION.md already at {new_version}")
        return 0

    new_major_minor = _major_minor(new_version)
    print(f"{VERSION_FILE.name}: {old_version} -> {new_version}")

    _replace(ENV_EXAMPLE, _ENV_APP_VERSION_RE, f"APP_VERSION={new_major_minor}")
    _replace(
        ROOT / "docker-compose.remote.yml",
        _COMPOSE_APP_VERSION_RE,
        f"${{APP_VERSION:-{new_major_minor}}}",
    )
    _replace(
        OPENAPI,
        re.compile(re.escape(f'"version": "{old_version}"')),
        f'"version": "{new_version}"',
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
