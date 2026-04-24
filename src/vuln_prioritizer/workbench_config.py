"""Environment-driven configuration for the Workbench web application."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from vuln_prioritizer.config import DEFAULT_CACHE_DIR, DEFAULT_NVD_API_KEY_ENV

DEFAULT_WORKBENCH_DB_URL = "sqlite:///./data/workbench.db"
DEFAULT_UPLOAD_DIR = Path("data") / "uploads"
DEFAULT_REPORT_DIR = Path("data") / "reports"
DEFAULT_MAX_UPLOAD_MB = 25
DEFAULT_CSRF_TOKEN = "local-workbench"


@dataclass(frozen=True, slots=True)
class WorkbenchSettings:
    """Runtime settings shared by API, web routes, and CLI helpers."""

    database_url: str = DEFAULT_WORKBENCH_DB_URL
    upload_dir: Path = DEFAULT_UPLOAD_DIR
    report_dir: Path = DEFAULT_REPORT_DIR
    provider_cache_dir: Path = DEFAULT_CACHE_DIR
    max_upload_mb: int = DEFAULT_MAX_UPLOAD_MB
    nvd_api_key_env: str = DEFAULT_NVD_API_KEY_ENV
    csrf_token: str = DEFAULT_CSRF_TOKEN

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


def load_workbench_settings() -> WorkbenchSettings:
    """Load Workbench settings from environment variables."""
    return WorkbenchSettings(
        database_url=os.getenv("VULN_PRIORITIZER_DB_URL", DEFAULT_WORKBENCH_DB_URL),
        upload_dir=Path(os.getenv("VULN_PRIORITIZER_UPLOAD_DIR", str(DEFAULT_UPLOAD_DIR))),
        report_dir=Path(os.getenv("VULN_PRIORITIZER_REPORT_DIR", str(DEFAULT_REPORT_DIR))),
        provider_cache_dir=Path(os.getenv("VULN_PRIORITIZER_CACHE_DIR", str(DEFAULT_CACHE_DIR))),
        max_upload_mb=_positive_int_from_env(
            "VULN_PRIORITIZER_MAX_UPLOAD_MB",
            DEFAULT_MAX_UPLOAD_MB,
        ),
        nvd_api_key_env=os.getenv("VULN_PRIORITIZER_NVD_API_KEY_ENV", DEFAULT_NVD_API_KEY_ENV),
        csrf_token=os.getenv("VULN_PRIORITIZER_CSRF_TOKEN", DEFAULT_CSRF_TOKEN),
    )


def ensure_workbench_directories(settings: WorkbenchSettings) -> None:
    """Create runtime directories used by uploads, reports, and provider cache."""
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    settings.provider_cache_dir.mkdir(parents=True, exist_ok=True)


def sqlite_path_from_url(database_url: str) -> Path | None:
    """Return a filesystem path for SQLite URLs, or None for non-SQLite URLs."""
    if database_url == "sqlite:///:memory:":
        return None
    if database_url.startswith("sqlite:///"):
        return Path(database_url.removeprefix("sqlite:///"))
    if database_url.startswith("sqlite:////"):
        return Path("/" + database_url.removeprefix("sqlite:////"))
    return None


def _positive_int_from_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default
