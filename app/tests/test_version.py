"""Tests for the single-source version file (app/VERSION.md)."""

from pathlib import Path

from config import Settings, _read_version_file


def test_read_version_file_reads_trimmed_content(tmp_path):
    version_file = tmp_path / "VERSION"
    version_file.write_text("0.0.9-beta\n")
    assert _read_version_file(version_file) == "0.0.9-beta"


def test_read_version_file_falls_back_when_missing(tmp_path):
    missing = tmp_path / "does-not-exist"
    assert _read_version_file(missing) == "0.0.0-dev"


def test_settings_app_version_matches_version_file(monkeypatch):
    monkeypatch.delenv("APP_VERSION", raising=False)
    version = Path(__file__).resolve().parents[1] / "VERSION.md"
    assert (
        Settings(app_env="development", secret_key="x").app_version == version.read_text().strip()
    )


def test_empty_app_version_env_falls_back_to_version_file(monkeypatch):
    monkeypatch.setenv("APP_VERSION", "")
    version = Path(__file__).resolve().parents[1] / "VERSION.md"
    assert (
        Settings(app_env="development", secret_key="x").app_version == version.read_text().strip()
    )


def test_app_version_env_override_wins(monkeypatch):
    monkeypatch.setenv("APP_VERSION", "9.9.9")
    assert Settings(app_env="development", secret_key="x").app_version == "9.9.9"


def test_build_provenance_defaults_to_unknown(monkeypatch):
    monkeypatch.delenv("BUILD_GIT_SHA", raising=False)
    monkeypatch.delenv("BUILD_DATE", raising=False)
    monkeypatch.delenv("BUILD_SOURCE_URL", raising=False)
    monkeypatch.delenv("BUILD_ENV", raising=False)
    settings = Settings(app_env="development", secret_key="x")
    assert settings.build_git_sha == "unknown"
    assert settings.build_date == "unknown"
    assert settings.build_source_url == "unknown"
    assert settings.build_env == "unknown"


def test_empty_build_provenance_env_falls_back_to_unknown(monkeypatch):
    monkeypatch.setenv("BUILD_GIT_SHA", "")
    monkeypatch.setenv("BUILD_DATE", "")
    monkeypatch.setenv("BUILD_SOURCE_URL", "")
    monkeypatch.setenv("BUILD_ENV", "")
    settings = Settings(app_env="development", secret_key="x")
    assert settings.build_git_sha == "unknown"
    assert settings.build_date == "unknown"
    assert settings.build_source_url == "unknown"
    assert settings.build_env == "unknown"


def test_build_provenance_env_override_wins(monkeypatch):
    monkeypatch.setenv("BUILD_GIT_SHA", "1edf171")
    monkeypatch.setenv("BUILD_DATE", "2026-08-22T09:15:00Z")
    monkeypatch.setenv("BUILD_SOURCE_URL", "https://github.com/trottomv/argus-sbomguard")
    monkeypatch.setenv("BUILD_ENV", "ci")
    settings = Settings(app_env="development", secret_key="x")
    assert settings.build_git_sha == "1edf171"
    assert settings.build_date == "2026-08-22T09:15:00Z"
    assert settings.build_source_url == "https://github.com/trottomv/argus-sbomguard"
    assert settings.build_env == "ci"
