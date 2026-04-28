"""Minimal template-style settings used before the full auth stack lands."""

from __future__ import annotations

from dataclasses import dataclass, field
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
    SECRET_KEY: str = "changethis"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8
    FIRST_SUPERUSER: str = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "changethis"
    FRONTEND_HOST: str = "http://localhost:5173"
    BACKEND_CORS_ORIGINS: tuple[str, ...] = field(default_factory=tuple)

    @property
    def all_cors_origins(self) -> tuple[str, ...]:
        """Return configured CORS origins plus the primary frontend host."""
        origins = [origin.rstrip("/") for origin in self.BACKEND_CORS_ORIGINS if origin]
        frontend_host = self.FRONTEND_HOST.rstrip("/")
        if frontend_host and frontend_host not in origins:
            origins.append(frontend_host)
        return tuple(origins)


def parse_cors_origins(raw_origins: str) -> tuple[str, ...]:
    """Parse comma-separated CORS origins using the template env var name."""
    return tuple(origin.strip().rstrip("/") for origin in raw_origins.split(",") if origin.strip())


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
        SECRET_KEY=environ.get("SECRET_KEY", "changethis"),
        ACCESS_TOKEN_EXPIRE_MINUTES=int(
            environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", str(60 * 24 * 8))
        ),
        FIRST_SUPERUSER=environ.get("FIRST_SUPERUSER", "admin@example.com"),
        FIRST_SUPERUSER_PASSWORD=environ.get("FIRST_SUPERUSER_PASSWORD", "changethis"),
        FRONTEND_HOST=environ.get("FRONTEND_HOST", "http://localhost:5173"),
        BACKEND_CORS_ORIGINS=parse_cors_origins(environ.get("BACKEND_CORS_ORIGINS", "")),
    )


settings = load_settings()
