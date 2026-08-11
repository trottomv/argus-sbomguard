#!/usr/bin/env python3
"""Propagate the version from app/VERSION.md to every file that mirrors it.

Usage: python3 scripts/bump_version.py

The version lives in one place — app/VERSION.md. Edit that file, then run this
script to rewrite every other file that mirrors it (the GHCR tag fallback in
the remote compose stack, the .env.example default, the README badge and the
docs APP_VERSION examples). The previous version is read from .env.example.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "app" / "VERSION.md"
ENV_EXAMPLE = ROOT / ".env.example"

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$")
_APP_VERSION_RE = re.compile(r"^APP_VERSION=(.*)$")


def _badge(version: str) -> str:
    return "version-" + version.replace("-", "--")


def _targets(old: str, new: str) -> list[tuple[Path, str, str]]:
    return [
        (ROOT / "README.md", _badge(old), _badge(new)),
        (ENV_EXAMPLE, f"APP_VERSION={old}", f"APP_VERSION={new}"),
        (
            ROOT / "docker-compose.remote.yml",
            f"${{APP_VERSION:-{old}}}",
            f"${{APP_VERSION:-{new}}}",
        ),
        (
            ROOT / "docs/deployment.md",
            f"`APP_VERSION` | `{old}`",
            f"`APP_VERSION` | `{new}`",
        ),
        (ROOT / "docs/setup.md", f"`APP_VERSION` | `{old}`", f"`APP_VERSION` | `{new}`"),
    ]


def _read_previous_version() -> str:
    for line in ENV_EXAMPLE.read_text().splitlines():
        match = _APP_VERSION_RE.match(line)
        if match:
            return match.group(1).strip()
    raise SystemExit(f"could not find APP_VERSION in {ENV_EXAMPLE.name}")


def main() -> int:
    new_version = VERSION_FILE.read_text().strip()
    if not _VERSION_RE.fullmatch(new_version):
        print(f"invalid version in {VERSION_FILE.name}: {new_version!r}", file=sys.stderr)
        return 2

    old_version = _read_previous_version()
    if old_version == new_version:
        print(f"app/VERSION.md already at {new_version}")
        return 0

    print(f"{VERSION_FILE.name}: {old_version} -> {new_version}")
    for path, old_str, new_str in _targets(old_version, new_version):
        text = path.read_text()
        count = text.count(old_str)
        if count == 0:
            print(f"warning: no match for {old_str!r} in {path.name}", file=sys.stderr)
            continue
        path.write_text(text.replace(old_str, new_str))
        print(f"{path.name}: {count} occurrence(s) updated")

    return 0


if __name__ == "__main__":
    sys.exit(main())
