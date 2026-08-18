"""Tests for the Lucide icon sprite referenced via ``<use href="#icon-…">``."""

import re
from pathlib import Path

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
SPRITE_PATH = TEMPLATES_DIR / "partials" / "icons_sprite.html"

_USE_HREF = re.compile(r'<use href="#icon-([a-z0-9-]+)"')
_SYMBOL_ID = re.compile(r'<symbol id="icon-([a-z0-9-]+)"')
_GEOMETRY = re.compile(r"<(path|circle|rect|line|polyline|polygon)\b")
_ICON_GLYPH = re.compile(
    r"&(?:larr|rarr|uarr|darr|nearhk|nwarr|searr|swarr|harr|varr);|[←→↑↓↗↘↙↖↔⇄]"
)


def _template_files():
    return sorted(p for p in TEMPLATES_DIR.rglob("*.html") if p != SPRITE_PATH)


def _defined_icons() -> set[str]:
    return set(_SYMBOL_ID.findall(SPRITE_PATH.read_text()))


def _used_icons() -> set[str]:
    used: set[str] = set()
    for path in _template_files():
        used.update(_USE_HREF.findall(path.read_text()))
    return used


def test_every_used_icon_is_defined_in_sprite():
    assert _used_icons() <= _defined_icons()


def test_every_defined_icon_is_used_somewhere():
    assert _defined_icons() <= _used_icons()


def test_no_inline_svg_geometry_outside_sprite():
    offenders = [
        f"{path.relative_to(TEMPLATES_DIR)}:{line_no}: {line.strip()[:80]}"
        for path in _template_files()
        for line_no, line in enumerate(path.read_text().splitlines(), 1)
        if _GEOMETRY.search(line)
    ]
    assert not offenders, offenders


def test_no_icon_glyph_entities_outside_sprite():
    offenders = [
        f"{path.relative_to(TEMPLATES_DIR)}:{line_no}: {line.strip()[:80]}"
        for path in _template_files()
        for line_no, line in enumerate(path.read_text().splitlines(), 1)
        if _ICON_GLYPH.search(line)
    ]
    assert not offenders, offenders
