"""Minimal template-style settings used before the full auth stack lands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Settings:
    """Settings shape aligned with the official template naming conventions."""

    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Vuln Prioritizer Workbench"
    ENVIRONMENT: Literal["local", "staging", "production"] = "local"
    LEGACY_API_PREFIX: str = "/api"


settings = Settings()
