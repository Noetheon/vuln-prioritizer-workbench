"""Optional ``vpw.toml`` settings for the packaged local runtime."""

from __future__ import annotations

import os
import stat
import tomllib
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from ipaddress import ip_network
from pathlib import Path
from typing import Any

from app.domain.engine.config import DEFAULT_GITHUB_TOKEN_ENV, DEFAULT_NVD_API_KEY_ENV

CONFIG_FILE_NAME = "vpw.toml"
LOG_LEVELS = ("debug", "info", "warning", "error")

# Setting name -> (expected type, environment variable). Secrets map to the
# variable the Workbench is configured to read, resolved when applied.
_IMPORT_SETTINGS: dict[str, tuple[type, str]] = {
    "max_upload_mb": (int, "MAX_UPLOAD_MB"),
    "grype_executable": (str, "SBOM_GRYPE_EXECUTABLE"),
    "sbom_scan_timeout_seconds": (int, "SBOM_SCAN_TIMEOUT_SECONDS"),
}
_SECRET_SETTINGS = ("nvd_api_key", "github_token")
_SERVE_SETTINGS: dict[str, type] = {
    "host": str,
    "port": int,
    "open_browser": bool,
    "log_level": str,
    "allowed_hosts": list,
}
AUTH_MODES = ("local", "proxy")
# Team-mode setting name -> (expected type, environment variable).
_AUTH_SETTINGS: dict[str, tuple[type, str]] = {
    "mode": (str, "AUTH_MODE"),
    "user_header": (str, "AUTH_PROXY_USER_HEADER"),
    "name_header": (str, "AUTH_PROXY_NAME_HEADER"),
    "trusted_proxies": (list, "TRUSTED_PROXY_CIDRS"),
    "logout_url": (str, "AUTH_PROXY_LOGOUT_URL"),
}


class LocalConfigError(ValueError):
    """Raised when ``vpw.toml`` cannot be read or has invalid settings."""


@dataclass(frozen=True, slots=True)
class LocalConfig:
    """Validated settings from one ``vpw.toml`` file."""

    path: Path | None = None
    host: str | None = None
    port: int | None = None
    open_browser: bool | None = None
    log_level: str | None = None
    allowed_hosts: tuple[str, ...] = ()
    auth: dict[str, str] = field(default_factory=dict)
    imports: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()


def load_local_config(path: Path, *, required: bool = False) -> LocalConfig:
    """Read and validate a config file; a missing optional file is empty."""
    if not path.is_file():
        if required:
            raise LocalConfigError(f"Config file not found: {path}.")
        return LocalConfig()
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise LocalConfigError(f"Cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise LocalConfigError(f"{path} is not valid TOML: {exc}") from exc
    unknown_tables = sorted(set(document) - {"serve", "providers", "imports", "auth"})
    if unknown_tables:
        raise LocalConfigError(f"Unknown section [{unknown_tables[0]}] in {path}.")
    serve = _table(document, "serve", path)
    providers = _table(document, "providers", path)
    imports = _table(document, "imports", path)
    auth = _table(document, "auth", path)
    _reject_unknown(serve, _SERVE_SETTINGS, "serve", path)
    _reject_unknown(auth, {key: kind for key, (kind, _env) in _AUTH_SETTINGS.items()}, "auth", path)
    _reject_unknown(providers, dict.fromkeys(_SECRET_SETTINGS, str), "providers", path)
    import_kinds = {key: kind for key, (kind, _env) in _IMPORT_SETTINGS.items()}
    _reject_unknown(imports, import_kinds, "imports", path)
    port = serve.get("port")
    if port is not None and not 1 <= port <= 65_535:
        raise LocalConfigError(f"[serve].port must be between 1 and 65535 in {path}.")
    log_level = serve.get("log_level")
    if log_level is not None and log_level not in LOG_LEVELS:
        raise LocalConfigError(f"[serve].log_level must be one of {', '.join(LOG_LEVELS)}.")
    for key, value in imports.items():
        if _IMPORT_SETTINGS[key][0] is int and value <= 0:
            raise LocalConfigError(f"[imports].{key} must be positive in {path}.")
    allowed_hosts = _string_list(serve.get("allowed_hosts", []), "serve.allowed_hosts", path)
    for host in allowed_hosts:
        if "://" in host or "/" in host or ":" in host:
            raise LocalConfigError(
                f"[serve].allowed_hosts entries are host names without scheme, port, or path "
                f"in {path}: {host}"
            )
    auth_environment = _auth_environment(auth, path)
    secrets = {key: value for key, value in providers.items() if value.strip()}
    warnings = (
        (
            f"{path} holds secrets and is readable by other users; "
            f"restrict it with: chmod 600 {path}",
        )
        if secrets and _readable_by_others(path)
        else ()
    )
    return LocalConfig(
        path=path,
        host=serve.get("host"),
        port=port,
        open_browser=serve.get("open_browser"),
        log_level=log_level,
        allowed_hosts=allowed_hosts,
        auth=auth_environment,
        imports=dict(imports),
        secrets=secrets,
        warnings=warnings,
    )


def apply_local_config_environment(
    config: LocalConfig,
    environ: MutableMapping[str, str] | None = None,
) -> list[str]:
    """Set configured values the environment does not already define; return their names."""
    target = os.environ if environ is None else environ
    values: dict[str, str] = {
        env_name: str(config.imports[key])
        for key, (_kind, env_name) in _IMPORT_SETTINGS.items()
        if key in config.imports
    }
    secret_env_names = {
        "nvd_api_key": target.get("WORKBENCH_NVD_API_KEY_ENV", DEFAULT_NVD_API_KEY_ENV),
        "github_token": target.get("WORKBENCH_GITHUB_TOKEN_ENV", DEFAULT_GITHUB_TOKEN_ENV),
    }
    for key, value in config.secrets.items():
        values[secret_env_names[key]] = value
    values.update(config.auth)
    applied: list[str] = []
    for name, value in values.items():
        if name in target:
            continue
        target[name] = value
        applied.append(name)
    return applied


def _auth_environment(auth: Mapping[str, Any], path: Path) -> dict[str, str]:
    mode = auth.get("mode")
    if mode is not None and mode not in AUTH_MODES:
        raise LocalConfigError(f"[auth].mode must be one of {', '.join(AUTH_MODES)} in {path}.")
    proxies = _string_list(auth.get("trusted_proxies", []), "auth.trusted_proxies", path)
    for cidr in proxies:
        try:
            ip_network(cidr, strict=False)
        except ValueError as exc:
            raise LocalConfigError(
                f"[auth].trusted_proxies has an invalid address or network in {path}: {cidr}"
            ) from exc
    environment = {
        _AUTH_SETTINGS[key][1]: value.strip()
        for key, value in auth.items()
        if isinstance(value, str) and value.strip()
    }
    if proxies:
        environment["TRUSTED_PROXY_CIDRS"] = ",".join(proxies)
    return environment


def _string_list(value: Any, name: str, path: Path) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise LocalConfigError(f"[{name.replace('.', '].', 1)} must be a list of names in {path}.")
    return tuple(dict.fromkeys(item.strip() for item in value))


def _table(document: Mapping[str, Any], name: str, path: Path) -> dict[str, Any]:
    value = document.get(name, {})
    if not isinstance(value, dict):
        raise LocalConfigError(f"[{name}] must be a table in {path}.")
    return value


def _reject_unknown(
    table: Mapping[str, Any],
    allowed: Mapping[str, type],
    section: str,
    path: Path,
) -> None:
    for key, value in table.items():
        kind = allowed.get(key)
        if kind is None:
            raise LocalConfigError(f"Unknown setting [{section}].{key} in {path}.")
        if isinstance(value, bool) is not (kind is bool) or not isinstance(value, kind):
            raise LocalConfigError(f"[{section}].{key} must be a {kind.__name__} in {path}.")


def _readable_by_others(path: Path) -> bool:
    if os.name == "nt":
        return False
    return bool(stat.S_IMODE(path.stat().st_mode) & (stat.S_IRWXG | stat.S_IRWXO))
