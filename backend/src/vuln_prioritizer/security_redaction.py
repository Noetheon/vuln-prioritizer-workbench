"""Shared redaction helpers for secret-bearing text, payloads, and paths."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SECRET_REDACTION_KEYS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "csrf",
    "password",
    "private_key",
    "secret",
    "token",
)
SECRET_REDACTION_KEY_EXCEPTIONS = {
    "nvd_api_key_env",
}
LOCAL_PATH_REDACTION_KEYS = (
    "input_path",
    "path",
    "provider_snapshot_file",
    "source_path",
    "upload_path",
)
REDACTED_VALUE = "[REDACTED]"
REDACTED_KEY = "[REDACTED-KEY]"

_SECRET_TEXT_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(api[_-]?key|apikey|password|private[_-]?key|secret|token)\b"),
    re.compile(r"(?i)\b(ghp_|github_pat_|xox[baprs]-|sk-[a-z0-9])"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_LOCAL_PATH_PATTERN = re.compile(
    r"(^|[\s\"'=])"
    r"(/Users/|/home/|/app/|/workspace/|/workspaces/|/srv/|/opt/|/private/|/tmp/|"
    r"/var/|/etc/|/root/|/mnt/|[A-Za-z]:\\)"
)
_LOCAL_PATH_TEXT_PATTERN = re.compile(
    r"(?P<prefix>^|[\s\"'=])"
    r"(?P<path>(?:~[/\\]|/Users/|/home/|/app/|/workspace/|/workspaces/|/srv/|/opt/|"
    r"/private/|/tmp/|/var/|/etc/|/root/|/mnt/|[A-Za-z]:\\)"
    r"[^\r\n\"'<>;,)]*)"
)
_URL_CREDENTIAL_PATTERN = re.compile(r"://[^/\s:@]+:[^/\s@]+@")
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([a-z0-9_]*(?:api[_-]?key|apikey|authorization|cookie|csrf[_-]?token|"
    r"password|private[_-]?key|secret|token)[a-z0-9_]*)\b\s*[:=]\s*([^\s,;&]+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+([a-z0-9._~+/=-]{8,})")
_SECRET_VALUE_PATTERN = re.compile(
    r"(?i)\b(ghp_|github_pat_|xox[baprs]-|sk-[a-z0-9])|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
)


def redact_value(
    value: Any,
    *,
    path_prefix: str = "",
    redact_paths: bool = True,
    redact_mapping_keys: bool = False,
) -> tuple[Any, list[str]]:
    """Recursively redact sensitive mapping keys and secret-shaped strings."""
    redacted_paths: list[str] = []

    def walk(candidate: Any, path: tuple[str, ...]) -> Any:
        if isinstance(candidate, dict):
            result: dict[str, Any] = {}
            for key, child in candidate.items():
                key_text = str(key)
                if redact_mapping_keys and _should_redact_mapping_key_text(
                    key_text,
                    redact_paths=redact_paths,
                ):
                    safe_key = _redacted_mapping_key(result)
                    redacted_paths.append(".".join((*path, safe_key)))
                    if should_redact_key(key_text):
                        result[safe_key] = REDACTED_VALUE
                    else:
                        result[safe_key] = walk(child, (*path, safe_key))
                    continue
                child_path = (*path, key_text)
                if should_redact_key(key_text):
                    result[key_text] = REDACTED_VALUE
                    redacted_paths.append(".".join(child_path))
                    continue
                result[key_text] = walk(child, child_path)
            return result
        if isinstance(candidate, list):
            return [walk(item, (*path, "[]")) for item in candidate]
        if isinstance(candidate, str) and should_redact_string(
            candidate,
            redact_paths=redact_paths,
        ):
            redacted_paths.append(".".join(path))
            return REDACTED_VALUE
        return candidate

    start = tuple(part for part in path_prefix.split(".") if part)
    return walk(value, start), redacted_paths


def _redacted_mapping_key(existing: dict[str, Any]) -> str:
    if REDACTED_KEY not in existing:
        return REDACTED_KEY
    index = 2
    while f"{REDACTED_KEY}-{index}" in existing:
        index += 1
    return f"{REDACTED_KEY}-{index}"


def _should_redact_mapping_key_text(key: str, *, redact_paths: bool) -> bool:
    stripped = key.strip()
    if not stripped:
        return False
    if redact_paths and (
        stripped.startswith(("/", "~/", "\\\\")) or _LOCAL_PATH_PATTERN.search(stripped)
    ):
        return True
    return bool(
        _ASSIGNMENT_PATTERN.search(stripped)
        or _BEARER_PATTERN.search(stripped)
        or _SECRET_VALUE_PATTERN.search(stripped)
        or _URL_CREDENTIAL_PATTERN.search(stripped)
    )


def redact_text(value: str, *, extra_secrets: Sequence[str | None] = ()) -> str:
    """Redact known secret values, local paths, and common assignment patterns."""
    redacted = value
    for secret in extra_secrets:
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    redacted = _BEARER_PATTERN.sub("Bearer <redacted>", redacted)
    redacted = _ASSIGNMENT_PATTERN.sub(r"\1=<redacted>", redacted)
    redacted = _URL_CREDENTIAL_PATTERN.sub("://<redacted>@", redacted)
    redacted = _LOCAL_PATH_TEXT_PATTERN.sub(r"\g<prefix>[REDACTED-PATH]", redacted)
    return redacted


def redact_error(value: BaseException | str, *, extra_secrets: Sequence[str | None] = ()) -> str:
    """Return a log/API-safe error string."""
    return redact_text(str(value), extra_secrets=extra_secrets)


def redacted_database_url(database_url: str) -> str:
    """Return a database URL with embedded credentials hidden."""
    try:
        parsed = urlsplit(database_url)
    except ValueError:
        return "<set>"
    if not parsed.netloc or "@" not in parsed.netloc:
        return database_url
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port is not None else ""
    username = parsed.username or ""
    userinfo = f"{username}:***@" if username else "***@"
    return urlunsplit((parsed.scheme, f"{userinfo}{host}{port}", parsed.path, parsed.query, ""))


def should_redact_key(key: str) -> bool:
    """Return whether a mapping key should be hidden regardless of value."""
    normalized = key.strip().lower()
    if normalized in SECRET_REDACTION_KEY_EXCEPTIONS:
        return False
    return any(fragment in normalized for fragment in SECRET_REDACTION_KEYS)


def should_redact_string(value: str, *, redact_paths: bool = True) -> bool:
    """Return whether a string itself looks like a secret, credential, or local path."""
    stripped = value.strip()
    if not stripped:
        return False
    if redact_paths and (
        stripped.startswith(("/", "~/", "\\\\")) or _LOCAL_PATH_PATTERN.search(stripped)
    ):
        return True
    if _URL_CREDENTIAL_PATTERN.search(stripped):
        return True
    return any(pattern.search(stripped) for pattern in _SECRET_TEXT_PATTERNS)
