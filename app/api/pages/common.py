def dep_name(name: str | None, version: str | None, purl: str | None) -> str:
    """Render a human-readable dependency name from raw component data."""
    if name:
        return f"{name} {version}" if version else name
    if purl:
        parts = purl.split("/")
        last = parts[-1].split("?")[0] if len(parts) >= 2 else purl
        if "@" in last:
            pkg, ver = last.split("@", 1)
            return f"{pkg} {ver}"
        return last
    return "-"
