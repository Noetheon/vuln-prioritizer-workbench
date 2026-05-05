"""Minimal template-style settings used before the full auth stack lands."""

from __future__ import annotations

from dataclasses import dataclass, field
from os import environ
from pathlib import Path
from typing import Literal, cast
from urllib.parse import quote_plus

EnvironmentName = Literal["local", "staging", "production"]
VALID_ENVIRONMENTS: set[str] = {"local", "staging", "production"}
DEFAULT_TEMPLATE_SECRET = "changethis"
INSECURE_TEMPLATE_SECRET_VALUES = {"", DEFAULT_TEMPLATE_SECRET}
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "testserver", "backend")
LOCAL_ONLY_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "testserver", "backend"}
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class Settings:
    """Settings shape aligned with the official template naming conventions."""

    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Vuln Prioritizer Workbench"
    ENVIRONMENT: EnvironmentName = "local"
    SECRET_KEY: str = "changethis"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8
    FIRST_SUPERUSER: str = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "changethis"
    FRONTEND_HOST: str = "http://localhost:5173"
    BACKEND_CORS_ORIGINS: tuple[str, ...] = field(default_factory=tuple)
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///./template.db"
    IMPORT_UPLOAD_DIR: str = "data/template-import-uploads"
    REPORT_DIR: str = "data/template-reports"
    PROVIDER_SNAPSHOT_DIR: str = "data"
    PROVIDER_CACHE_DIR: str = "data/template-provider-cache"
    ATTACK_ARTIFACT_DIR: str = "data/attack"
    MAX_UPLOAD_MB: int = 25
    ALLOWED_HOSTS: tuple[str, ...] = field(default_factory=lambda: DEFAULT_ALLOWED_HOSTS)
    API_DOCS_ENABLED: bool | None = None

    def __post_init__(self) -> None:
        """Reject unsafe deployment settings before the app serves traffic."""
        environment = _validate_environment_name(self.ENVIRONMENT)
        allowed_hosts = _validate_allowed_hosts(self.ALLOWED_HOSTS)
        object.__setattr__(self, "ENVIRONMENT", environment)
        object.__setattr__(self, "ALLOWED_HOSTS", allowed_hosts)
        _validate_secret_defaults(self)

    @property
    def all_cors_origins(self) -> tuple[str, ...]:
        """Return configured CORS origins plus the primary frontend host."""
        origins = [origin.rstrip("/") for origin in self.BACKEND_CORS_ORIGINS if origin]
        frontend_host = self.FRONTEND_HOST.rstrip("/")
        if frontend_host and frontend_host not in origins:
            origins.append(frontend_host)
        return tuple(origins)

    @property
    def api_docs_enabled(self) -> bool:
        """Return whether docs and OpenAPI routes should be exposed over HTTP."""
        if self.API_DOCS_ENABLED is not None:
            return self.API_DOCS_ENABLED
        return self.ENVIRONMENT == "local"

    @property
    def import_upload_dir_path(self) -> Path:
        """Return the configured template import upload root."""
        return Path(self.IMPORT_UPLOAD_DIR)

    @property
    def report_dir_path(self) -> Path:
        """Return the configured template report artifact root."""
        return Path(self.REPORT_DIR)

    @property
    def provider_snapshot_dir_path(self) -> Path:
        """Return the configured provider snapshot root for template imports."""
        return Path(self.PROVIDER_SNAPSHOT_DIR)

    @property
    def provider_cache_dir_path(self) -> Path:
        """Return the configured provider cache root for template imports."""
        return Path(self.PROVIDER_CACHE_DIR)

    @property
    def attack_artifact_dir_path(self) -> Path:
        """Return the configured ATT&CK artifact root for template imports."""
        return Path(self.ATTACK_ARTIFACT_DIR)

    @property
    def max_upload_bytes(self) -> int:
        """Return the configured per-file upload limit in bytes."""
        return self.MAX_UPLOAD_MB * 1024 * 1024


def parse_cors_origins(raw_origins: str) -> tuple[str, ...]:
    """Parse comma-separated CORS origins using the template env var name."""
    return tuple(origin.strip().rstrip("/") for origin in raw_origins.split(",") if origin.strip())


def parse_allowed_hosts(raw_hosts: str) -> tuple[str, ...]:
    """Parse comma-separated trusted hosts for Starlette host validation."""
    return tuple(host.strip().lower() for host in raw_hosts.split(",") if host.strip())


def build_database_uri() -> str:
    """Build the template-style database URL from explicit or Postgres env vars."""
    explicit_uri = environ.get("SQLALCHEMY_DATABASE_URI") or environ.get("DATABASE_URL")
    if explicit_uri:
        return explicit_uri

    postgres_server = environ.get("POSTGRES_SERVER")
    if postgres_server:
        user = quote_plus(environ.get("POSTGRES_USER", "postgres"))
        password = quote_plus(environ.get("POSTGRES_PASSWORD", "postgres"))
        port = environ.get("POSTGRES_PORT", "5432")
        db = quote_plus(environ.get("POSTGRES_DB", "app"))
        return f"postgresql+psycopg://{user}:{password}@{postgres_server}:{port}/{db}"

    return "sqlite:///./template.db"


def load_settings() -> Settings:
    """Load the minimal template-shell settings from environment variables."""
    environment = _validate_environment_name(environ.get("ENVIRONMENT", "local"))
    allowed_hosts = _allowed_hosts_from_env()
    return Settings(
        API_V1_STR=environ.get("API_V1_STR", "/api/v1"),
        PROJECT_NAME=environ.get("PROJECT_NAME", "Vuln Prioritizer Workbench"),
        ENVIRONMENT=environment,
        SECRET_KEY=environ.get("SECRET_KEY", DEFAULT_TEMPLATE_SECRET),
        ACCESS_TOKEN_EXPIRE_MINUTES=int(
            environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", str(60 * 24 * 8))
        ),
        FIRST_SUPERUSER=environ.get("FIRST_SUPERUSER", "admin@example.com"),
        FIRST_SUPERUSER_PASSWORD=environ.get(
            "FIRST_SUPERUSER_PASSWORD",
            DEFAULT_TEMPLATE_SECRET,
        ),
        FRONTEND_HOST=environ.get("FRONTEND_HOST", "http://localhost:5173"),
        BACKEND_CORS_ORIGINS=parse_cors_origins(environ.get("BACKEND_CORS_ORIGINS", "")),
        SQLALCHEMY_DATABASE_URI=build_database_uri(),
        IMPORT_UPLOAD_DIR=environ.get("IMPORT_UPLOAD_DIR", "data/template-import-uploads"),
        REPORT_DIR=environ.get("REPORT_DIR", "data/template-reports"),
        PROVIDER_SNAPSHOT_DIR=environ.get("PROVIDER_SNAPSHOT_DIR", "data"),
        PROVIDER_CACHE_DIR=environ.get("PROVIDER_CACHE_DIR", "data/template-provider-cache"),
        ATTACK_ARTIFACT_DIR=environ.get("ATTACK_ARTIFACT_DIR", "data/attack"),
        MAX_UPLOAD_MB=_positive_int_from_env("MAX_UPLOAD_MB", 25),
        ALLOWED_HOSTS=allowed_hosts,
        API_DOCS_ENABLED=_optional_bool_from_env("API_DOCS_ENABLED"),
    )


def _positive_int_from_env(name: str, default: int) -> int:
    raw_value = environ.get(name)
    if raw_value is None:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _optional_bool_from_env(name: str) -> bool | None:
    raw_value = environ.get(name)
    if raw_value is None or raw_value.strip() == "":
        return None
    normalized = raw_value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be true or false.")


def _allowed_hosts_from_env() -> tuple[str, ...]:
    raw_hosts = environ.get("ALLOWED_HOSTS")
    if raw_hosts is None:
        raw_hosts = environ.get("VULN_PRIORITIZER_ALLOWED_HOSTS")
    if raw_hosts is None or raw_hosts.strip() == "":
        return DEFAULT_ALLOWED_HOSTS
    return parse_allowed_hosts(raw_hosts)


def _is_insecure_template_secret(value: str) -> bool:
    return value.strip().lower() in INSECURE_TEMPLATE_SECRET_VALUES


def _validate_environment_name(value: str) -> EnvironmentName:
    environment = value.strip().lower()
    if environment not in VALID_ENVIRONMENTS:
        allowed = ", ".join(sorted(VALID_ENVIRONMENTS))
        raise ValueError(f"ENVIRONMENT must be one of: {allowed}.")
    return cast(EnvironmentName, environment)


def _validate_allowed_hosts(hosts: tuple[str, ...]) -> tuple[str, ...]:
    deduped: list[str] = []
    for raw_host in hosts:
        host = raw_host.strip().lower()
        if not host:
            continue
        if "://" in host or "/" in host:
            raise ValueError("ALLOWED_HOSTS entries must not include schemes or paths.")
        if ":" in host:
            raise ValueError("ALLOWED_HOSTS entries must not include ports.")
        if host == "*":
            raise ValueError("ALLOWED_HOSTS must not use the catch-all '*' host.")
        if "*" in host and host != "*" and not host.startswith("*."):
            raise ValueError("ALLOWED_HOSTS wildcard entries must start with '*.'.")
        if host.startswith("*.") and len(host) <= 2:
            raise ValueError("ALLOWED_HOSTS wildcard entries must include a domain suffix.")
        if host not in deduped:
            deduped.append(host)
    if not deduped:
        raise ValueError("ALLOWED_HOSTS must include at least one host.")
    return tuple(deduped)


def _validate_secret_defaults(settings: Settings) -> None:
    if not _settings_use_insecure_template_secret(settings):
        return

    if settings.ENVIRONMENT == "local" and _allowed_hosts_are_local_only(settings.ALLOWED_HOSTS):
        return

    insecure_fields = _insecure_secret_fields(settings)
    fields = ", ".join(insecure_fields)
    if settings.ENVIRONMENT == "local":
        raise ValueError(
            f"{fields} must be set to non-default secret values when local mode "
            "is configured with non-local ALLOWED_HOSTS."
        )

    raise ValueError(
        f"{fields} must be set to non-default secret values when "
        f"ENVIRONMENT={settings.ENVIRONMENT}."
    )


def _settings_use_insecure_template_secret(settings: Settings) -> bool:
    return bool(_insecure_secret_fields(settings))


def _insecure_secret_fields(settings: Settings) -> list[str]:
    insecure_fields = [
        name
        for name, value in (
            ("SECRET_KEY", settings.SECRET_KEY),
            ("FIRST_SUPERUSER_PASSWORD", settings.FIRST_SUPERUSER_PASSWORD),
        )
        if _is_insecure_template_secret(value)
    ]
    return insecure_fields


def _allowed_hosts_are_local_only(hosts: tuple[str, ...]) -> bool:
    return all(_is_local_allowed_host(host) for host in hosts)


def _is_local_allowed_host(host: str) -> bool:
    if host in LOCAL_ONLY_ALLOWED_HOSTS:
        return True
    if host == "*.localhost":
        return True
    if host.startswith("*."):
        return False
    return host.endswith(".localhost")


settings = load_settings()
