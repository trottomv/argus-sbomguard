from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from fastapi.templating import Jinja2Templates

from config import settings

_DISPLAY_TZ = ZoneInfo(settings.display_timezone)


def format_dt(value: datetime | None, fmt: str, fallback: str = "-") -> str:
    if value is None:
        return fallback
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(_DISPLAY_TZ).strftime(fmt)


templates = Jinja2Templates(directory="templates")
templates.env.filters["format_dt"] = format_dt
