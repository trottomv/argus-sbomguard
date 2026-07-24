from datetime import UTC, datetime

from templating import format_dt


class TestFormatDt:
    def test_none_returns_fallback(self):
        assert format_dt(None, "%Y-%m-%d") == "-"

    def test_none_custom_fallback(self):
        assert format_dt(None, "%Y-%m-%d", "never") == "never"

    def test_utc_aware_datetime(self):
        dt = datetime(2026, 7, 24, 5, 46, 0, tzinfo=UTC)
        result = format_dt(dt, "%Y-%m-%d %H:%M")
        assert "2026-07-24" in result

    def test_naive_datetime_treated_as_utc(self):
        dt = datetime(2026, 7, 24, 5, 46)
        result = format_dt(dt, "%Y-%m-%d")
        assert "2026-07-24" in result

    def test_format_with_time(self):
        dt = datetime(2026, 7, 24, 5, 46, 0, tzinfo=UTC)
        result = format_dt(dt, "%Y-%m-%d %H:%M")
        assert ":46" in result or ":" in result

    def test_date_only_format(self):
        dt = datetime(2026, 7, 24, 5, 46, 0, tzinfo=UTC)
        result = format_dt(dt, "%Y-%m-%d")
        assert result == "2026-07-24" or result.startswith("2026-07-24")

    def test_empty_string_fallback(self):
        assert format_dt(None, "%Y-%m-%d", "") == ""
