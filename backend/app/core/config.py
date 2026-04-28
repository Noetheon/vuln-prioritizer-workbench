"""Minimal template-style settings used before the full auth stack lands."""

from __future__ import annotations

from dataclasses import dataclass
from os import environ
from typing import Literal, cast

EnvironmentName = Literal["local", "staging", "production"]
VALID_ENVIRONMENTS: set[str] = {"local", "staging", "production"}


@dataclass(frozen=True)
class Settings:
    """Settings shape aligned with the official template naming conventions."""

    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Vuln Prioritizer Workbench"
    ENVIRONMENT: EnvironmentName = "local"
    LEGACY_API_PREFIX: str = "/api"


def load_settings() -> Settings:
    """Load the minimal template-shell settings from environment variables."""
    raw_environment = environ.get("ENVIRONMENT", "local")
    environment = cast(
        EnvironmentName,
        raw_environment if raw_environment in VALID_ENVIRONMENTS else "local",
    )
    return Settings(
        API_V1_STR=environ.get("API_V1_STR", "/api/v1"),
        PROJECT_NAME=environ.get("PROJECT_NAME", "Vuln Prioritizer Workbench"),
        ENVIRONMENT=environment,
        LEGACY_API_PREFIX=environ.get("LEGACY_API_PREFIX", "/api"),
    )


settings = load_settings()
