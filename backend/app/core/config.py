"""Minimal Workbench settings used before the full auth stack lands."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network
from os import environ
from pathlib import Path
from typing import Literal, cast
from urllib.parse import quote_plus, urlparse

EnvironmentName = Literal["local", "staging", "production"]
VALID_ENVIRONMENTS: set[str] = {"local", "staging", "production"}
DEFAULT_WORKBENCH_SECRET = "changethis"
LOCAL_WORKBENCH_SECRET_PLACEHOLDER = "local-workbench-dev-secret"
LOCAL_WORKBENCH_PASSWORD_PLACEHOLDER = "local-workbench-dev-password"
LOCAL_WORKBENCH_POSTGRES_PASSWORD_PLACEHOLDER = "local-workbench-dev-postgres-password"
INSECURE_WORKBENCH_SECRET_VALUES = {
    "",
    DEFAULT_WORKBENCH_SECRET,
    LOCAL_WORKBENCH_SECRET_PLACEHOLDER,
    LOCAL_WORKBENCH_PASSWORD_PLACEHOLDER,
}
INSECURE_POSTGRES_PASSWORD_VALUES = {
    "",
    "postgres",
    "workbench",
    DEFAULT_WORKBENCH_SECRET,
    LOCAL_WORKBENCH_POSTGRES_PASSWORD_PLACEHOLDER,
}
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "testserver", "backend")
LOCAL_ONLY_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "testserver", "backend"}
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}
DEFAULT_SQLITE_DATABASE_URI = "sqlite:///./workbench.db"
LEGACY_SQLITE_DATABASE_URI = "sqlite:///./template.db"
DEFAULT_IMPORT_UPLOAD_DIR = "data/workbench-import-uploads"
LEGACY_IMPORT_UPLOAD_DIR = "data/template-import-uploads"
DEFAULT_REPORT_DIR = "data/workbench-reports"
LEGACY_REPORT_DIR = "data/template-reports"
DEFAULT_PROVIDER_CACHE_DIR = "data/workbench-provider-cache"
LEGACY_PROVIDER_CACHE_DIR = "data/template-provider-cache"
LEGACY_STORAGE_FALLBACK_ENV = "WORKBENCH_LEGACY_STORAGE_FALLBACK"
MIN_SECRET_KEY_LENGTH = 32
MIN_FIRST_SUPERUSER_PASSWORD_LENGTH = 16
DEFAULT_API_TOKEN_EXPIRE_DAYS = 90


@dataclass(frozen=True)
class Settings:
    """Settings shape aligned with the Workbench environment conventions."""

    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Vuln Prioritizer Workbench"
    ENVIRONMENT: EnvironmentName = "local"
    SECRET_KEY: str = "changethis"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8
    FIRST_SUPERUSER: str = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "changethis"
    FRONTEND_HOST: str = "http://localhost:5173"
    BACKEND_CORS_ORIGINS: tuple[str, ...] = field(default_factory=tuple)
    SQLALCHEMY_DATABASE_URI: str = DEFAULT_SQLITE_DATABASE_URI
    IMPORT_UPLOAD_DIR: str = DEFAULT_IMPORT_UPLOAD_DIR
    REPORT_DIR: str = DEFAULT_REPORT_DIR
    PROVIDER_SNAPSHOT_DIR: str = "data"
    PROVIDER_CACHE_DIR: str = DEFAULT_PROVIDER_CACHE_DIR
    ATTACK_ARTIFACT_DIR: str = "data/attack"
    DEMO_PROVIDER_SNAPSHOT_ENABLED: bool = False
    MAX_UPLOAD_MB: int = 25
    RATE_LIMIT_ENABLED: bool = True
    API_RATE_LIMIT_PER_MINUTE: int = 600
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 60
    TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE: int = 60
    DECISION_API_MAX_FINDINGS: int = 1000
    API_TOKEN_DEFAULT_EXPIRE_DAYS: int = DEFAULT_API_TOKEN_EXPIRE_DAYS
    BACKGROUND_IMPORT_STALE_MINUTES: int = 120
    TRUSTED_PROXY_CIDRS: tuple[str, ...] = field(default_factory=tuple)
    AUDIT_RETENTION_DAYS: int = 365
    SESSION_RETENTION_DAYS: int = 30
    REVOKED_API_TOKEN_RETENTION_DAYS: int = 365
    ALLOWED_HOSTS: tuple[str, ...] = field(default_factory=lambda: DEFAULT_ALLOWED_HOSTS)
    API_DOCS_ENABLED: bool | None = None

    def __post_init__(self) -> None:
        """Reject unsafe deployment settings before the app serves traffic."""
        environment = _validate_environment_name(self.ENVIRONMENT)
        allowed_hosts = _validate_allowed_hosts(self.ALLOWED_HOSTS)
        trusted_proxy_cidrs = _validate_trusted_proxy_cidrs(self.TRUSTED_PROXY_CIDRS)
        object.__setattr__(self, "ENVIRONMENT", environment)
        object.__setattr__(self, "ALLOWED_HOSTS", allowed_hosts)
        object.__setattr__(self, "TRUSTED_PROXY_CIDRS", trusted_proxy_cidrs)
        _validate_secret_defaults(self)
        frontend_host, cors_origins = _validate_cors_origins(
            self.FRONTEND_HOST,
            self.BACKEND_CORS_ORIGINS,
            environment,
        )
        object.__setattr__(self, "FRONTEND_HOST", frontend_host)
        object.__setattr__(self, "BACKEND_CORS_ORIGINS", cors_origins)

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
        """Return the configured Workbench import upload root."""
        return Path(self.IMPORT_UPLOAD_DIR)

    @property
    def report_dir_path(self) -> Path:
        """Return the configured Workbench report artifact root."""
        return Path(self.REPORT_DIR)

    @property
    def provider_snapshot_dir_path(self) -> Path:
        """Return the configured provider snapshot root for Workbench imports."""
        return Path(self.PROVIDER_SNAPSHOT_DIR)

    @property
    def provider_cache_dir_path(self) -> Path:
        """Return the configured provider cache root for Workbench imports."""
        return Path(self.PROVIDER_CACHE_DIR)

    @property
    def attack_artifact_dir_path(self) -> Path:
        """Return the configured ATT&CK artifact root for Workbench imports."""
        return Path(self.ATTACK_ARTIFACT_DIR)

    @property
    def max_upload_bytes(self) -> int:
        """Return the configured per-file upload limit in bytes."""
        return self.MAX_UPLOAD_MB * 1024 * 1024


def parse_cors_origins(raw_origins: str) -> tuple[str, ...]:
    """Parse comma-separated CORS origins using the Workbench env var name."""
    return tuple(origin.strip().rstrip("/") for origin in raw_origins.split(",") if origin.strip())


def parse_allowed_hosts(raw_hosts: str) -> tuple[str, ...]:
    """Parse comma-separated trusted hosts for Starlette host validation."""
    return tuple(host.strip().lower() for host in raw_hosts.split(",") if host.strip())


def parse_trusted_proxy_cidrs(raw_cidrs: str) -> tuple[str, ...]:
    """Parse comma-separated trusted reverse-proxy CIDRs."""
    return tuple(cidr.strip() for cidr in raw_cidrs.split(",") if cidr.strip())


def build_database_uri() -> str:
    """Build the Workbench database URL from explicit or Postgres env vars."""
    explicit_uri = environ.get("SQLALCHEMY_DATABASE_URI") or environ.get("DATABASE_URL")
    if explicit_uri:
        return explicit_uri

    postgres_server = environ.get("POSTGRES_SERVER")
    if postgres_server:
        user = quote_plus(environ.get("POSTGRES_USER", "postgres"))
        raw_password = environ.get("POSTGRES_PASSWORD", "postgres")
        _validate_postgres_password_default(raw_password)
        password = quote_plus(raw_password)
        port = environ.get("POSTGRES_PORT", "5432")
        db = quote_plus(environ.get("POSTGRES_DB", "app"))
        return f"postgresql+psycopg://{user}:{password}@{postgres_server}:{port}/{db}"

    return _default_sqlite_database_uri()


def load_settings() -> Settings:
    """Load the minimal Workbench settings from environment variables."""
    environment = _validate_environment_name(environ.get("ENVIRONMENT", "local"))
    allowed_hosts = _allowed_hosts_from_env()
    return Settings(
        API_V1_STR=environ.get("API_V1_STR", "/api/v1"),
        PROJECT_NAME=environ.get("PROJECT_NAME", "Vuln Prioritizer Workbench"),
        ENVIRONMENT=environment,
        SECRET_KEY=environ.get("SECRET_KEY", DEFAULT_WORKBENCH_SECRET),
        ACCESS_TOKEN_EXPIRE_MINUTES=int(
            environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", str(60 * 24 * 8))
        ),
        FIRST_SUPERUSER=environ.get("FIRST_SUPERUSER", "admin@example.com"),
        FIRST_SUPERUSER_PASSWORD=environ.get(
            "FIRST_SUPERUSER_PASSWORD",
            DEFAULT_WORKBENCH_SECRET,
        ),
        FRONTEND_HOST=environ.get("FRONTEND_HOST", "http://localhost:5173"),
        BACKEND_CORS_ORIGINS=parse_cors_origins(environ.get("BACKEND_CORS_ORIGINS", "")),
        SQLALCHEMY_DATABASE_URI=build_database_uri(),
        IMPORT_UPLOAD_DIR=_storage_path_from_env(
            "IMPORT_UPLOAD_DIR",
            DEFAULT_IMPORT_UPLOAD_DIR,
            LEGACY_IMPORT_UPLOAD_DIR,
        ),
        REPORT_DIR=_storage_path_from_env("REPORT_DIR", DEFAULT_REPORT_DIR, LEGACY_REPORT_DIR),
        PROVIDER_SNAPSHOT_DIR=environ.get("PROVIDER_SNAPSHOT_DIR", "data"),
        PROVIDER_CACHE_DIR=_storage_path_from_env(
            "PROVIDER_CACHE_DIR",
            DEFAULT_PROVIDER_CACHE_DIR,
            LEGACY_PROVIDER_CACHE_DIR,
        ),
        ATTACK_ARTIFACT_DIR=environ.get("ATTACK_ARTIFACT_DIR", "data/attack"),
        DEMO_PROVIDER_SNAPSHOT_ENABLED=_bool_from_env(
            "DEMO_PROVIDER_SNAPSHOT_ENABLED",
            False,
        ),
        MAX_UPLOAD_MB=_positive_int_from_env("MAX_UPLOAD_MB", 25),
        RATE_LIMIT_ENABLED=_bool_from_env("RATE_LIMIT_ENABLED", True),
        API_RATE_LIMIT_PER_MINUTE=_positive_int_from_env("API_RATE_LIMIT_PER_MINUTE", 600),
        LOGIN_RATE_LIMIT_PER_MINUTE=_positive_int_from_env("LOGIN_RATE_LIMIT_PER_MINUTE", 60),
        TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE=_positive_int_from_env(
            "TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE",
            60,
        ),
        DECISION_API_MAX_FINDINGS=_positive_int_from_env("DECISION_API_MAX_FINDINGS", 1000),
        API_TOKEN_DEFAULT_EXPIRE_DAYS=_positive_int_from_env(
            "API_TOKEN_DEFAULT_EXPIRE_DAYS",
            DEFAULT_API_TOKEN_EXPIRE_DAYS,
        ),
        BACKGROUND_IMPORT_STALE_MINUTES=_positive_int_from_env(
            "BACKGROUND_IMPORT_STALE_MINUTES",
            120,
        ),
        TRUSTED_PROXY_CIDRS=parse_trusted_proxy_cidrs(environ.get("TRUSTED_PROXY_CIDRS", "")),
        AUDIT_RETENTION_DAYS=_positive_int_from_env("AUDIT_RETENTION_DAYS", 365),
        SESSION_RETENTION_DAYS=_positive_int_from_env("SESSION_RETENTION_DAYS", 30),
        REVOKED_API_TOKEN_RETENTION_DAYS=_positive_int_from_env(
            "REVOKED_API_TOKEN_RETENTION_DAYS",
            365,
        ),
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


def _default_sqlite_database_uri() -> str:
    if not _legacy_storage_fallback_enabled():
        return DEFAULT_SQLITE_DATABASE_URI
    legacy_path = Path("template.db")
    default_path = Path("workbench.db")
    if legacy_path.exists() and not default_path.exists():
        return LEGACY_SQLITE_DATABASE_URI
    return DEFAULT_SQLITE_DATABASE_URI


def _storage_path_from_env(name: str, default_path: str, legacy_path: str) -> str:
    configured_path = environ.get(name)
    if configured_path:
        return configured_path
    if not _legacy_storage_fallback_enabled():
        return default_path
    legacy_root = Path(legacy_path)
    default_root = Path(default_path)
    if not default_root.exists() and _path_contains_data(legacy_root):
        return legacy_path
    return default_path


def _legacy_storage_fallback_enabled() -> bool:
    return _bool_from_env(LEGACY_STORAGE_FALLBACK_ENV, False)


def _path_contains_data(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    return any(path.iterdir())


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


def _bool_from_env(name: str, default: bool) -> bool:
    parsed = _optional_bool_from_env(name)
    return default if parsed is None else parsed


def _allowed_hosts_from_env() -> tuple[str, ...]:
    raw_hosts = environ.get("ALLOWED_HOSTS")
    if raw_hosts is None:
        raw_hosts = environ.get("VULN_PRIORITIZER_ALLOWED_HOSTS")
    if raw_hosts is None or raw_hosts.strip() == "":
        return DEFAULT_ALLOWED_HOSTS
    return parse_allowed_hosts(raw_hosts)


def _is_insecure_workbench_secret(value: str) -> bool:
    return value.strip().lower() in INSECURE_WORKBENCH_SECRET_VALUES


def _secret_policy_applies(settings: Settings) -> bool:
    return settings.ENVIRONMENT != "local" or not _allowed_hosts_are_local_only(
        settings.ALLOWED_HOSTS
    )


def _validate_postgres_password_default(value: str) -> None:
    environment = _validate_environment_name(environ.get("ENVIRONMENT", "local"))
    if environment == "local":
        return
    if value.strip().lower() in INSECURE_POSTGRES_PASSWORD_VALUES:
        raise ValueError(
            f"POSTGRES_PASSWORD must be set to a non-default value when ENVIRONMENT={environment}."
        )


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


def _validate_trusted_proxy_cidrs(cidrs: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for raw_cidr in cidrs:
        cidr = raw_cidr.strip()
        if not cidr:
            continue
        try:
            network = ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"TRUSTED_PROXY_CIDRS contains an invalid CIDR: {cidr}.") from exc
        rendered = str(network)
        if rendered not in normalized:
            normalized.append(rendered)
    return tuple(normalized)


def _validate_secret_defaults(settings: Settings) -> None:
    if not _settings_use_insecure_workbench_secret(settings) and not _weak_secret_fields(settings):
        return

    if not _secret_policy_applies(settings):
        return

    insecure_fields = _insecure_secret_fields(settings)
    weak_fields = _weak_secret_fields(settings)
    fields = ", ".join(dict.fromkeys([*insecure_fields, *weak_fields]))
    if settings.ENVIRONMENT == "local":
        raise ValueError(
            f"{fields} must be set to strong non-default secret values when local mode "
            "is configured with non-local ALLOWED_HOSTS."
        )

    raise ValueError(
        f"{fields} must be set to strong non-default secret values when "
        f"ENVIRONMENT={settings.ENVIRONMENT}."
    )


def _validate_cors_origins(
    frontend_host: str,
    origins: tuple[str, ...],
    environment: EnvironmentName,
) -> tuple[str, tuple[str, ...]]:
    normalized_frontend = frontend_host.rstrip("/")
    normalized_origins = tuple(origin.rstrip("/") for origin in origins if origin)
    for origin in (*normalized_origins, normalized_frontend):
        if origin:
            _validate_cors_origin(origin, environment)
    return normalized_frontend, normalized_origins


def _validate_cors_origin(origin: str, environment: EnvironmentName) -> None:
    if origin == "*" or "*" in origin:
        raise ValueError("BACKEND_CORS_ORIGINS and FRONTEND_HOST must use exact origins.")
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
        raise ValueError("BACKEND_CORS_ORIGINS and FRONTEND_HOST entries must be origins.")
    hostname = (parsed.hostname or "").lower()
    if environment in {"staging", "production"}:
        if parsed.scheme != "https":
            raise ValueError("Non-local CORS origins must use https.")
        if hostname in {"localhost", "127.0.0.1"} or hostname.endswith(".localhost"):
            raise ValueError("Non-local CORS origins must not use localhost.")


def _settings_use_insecure_workbench_secret(settings: Settings) -> bool:
    return bool(_insecure_secret_fields(settings))


def _insecure_secret_fields(settings: Settings) -> list[str]:
    insecure_fields = [
        name
        for name, value in (
            ("SECRET_KEY", settings.SECRET_KEY),
            ("FIRST_SUPERUSER_PASSWORD", settings.FIRST_SUPERUSER_PASSWORD),
        )
        if _is_insecure_workbench_secret(value)
    ]
    return insecure_fields


def _weak_secret_fields(settings: Settings) -> list[str]:
    """Return secret fields that are non-default but too weak for non-local use."""
    weak_fields: list[str] = []
    if len(settings.SECRET_KEY.strip()) < MIN_SECRET_KEY_LENGTH:
        weak_fields.append("SECRET_KEY")
    password = settings.FIRST_SUPERUSER_PASSWORD.strip()
    if len(password) < MIN_FIRST_SUPERUSER_PASSWORD_LENGTH:
        weak_fields.append("FIRST_SUPERUSER_PASSWORD")
    if password.lower() == settings.FIRST_SUPERUSER.strip().lower():
        weak_fields.append("FIRST_SUPERUSER_PASSWORD")
    if password and password == settings.SECRET_KEY:
        weak_fields.append("FIRST_SUPERUSER_PASSWORD")
    return weak_fields


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
