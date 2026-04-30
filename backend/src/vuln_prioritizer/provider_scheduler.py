"""Small HTTP scheduler client for Workbench provider update jobs."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

DEFAULT_BASE_URL = "http://workbench-postgres:8000"
DEFAULT_INTERVAL_SECONDS = 24 * 60 * 60
DEFAULT_SOURCES = ("nvd", "epss", "kev")


@dataclass(frozen=True, slots=True)
class ProviderSchedulerConfig:
    base_url: str = DEFAULT_BASE_URL
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS
    sources: tuple[str, ...] = DEFAULT_SOURCES
    cache_only: bool = True
    max_cves: int | None = None
    api_token: str | None = None
    once: bool = False


def load_scheduler_config(env: Mapping[str, str] | None = None) -> ProviderSchedulerConfig:
    values = env or os.environ
    return ProviderSchedulerConfig(
        base_url=values.get("VULN_PRIORITIZER_PROVIDER_UPDATE_BASE_URL", DEFAULT_BASE_URL),
        interval_seconds=_positive_int(
            values.get("VULN_PRIORITIZER_PROVIDER_UPDATE_INTERVAL_SECONDS"),
            DEFAULT_INTERVAL_SECONDS,
            "VULN_PRIORITIZER_PROVIDER_UPDATE_INTERVAL_SECONDS",
        ),
        sources=_sources(values.get("VULN_PRIORITIZER_PROVIDER_UPDATE_SOURCES")),
        cache_only=_bool(values.get("VULN_PRIORITIZER_PROVIDER_UPDATE_CACHE_ONLY"), default=True),
        max_cves=_optional_positive_int(
            values.get("VULN_PRIORITIZER_PROVIDER_UPDATE_MAX_CVES"),
            "VULN_PRIORITIZER_PROVIDER_UPDATE_MAX_CVES",
        ),
        api_token=values.get("VULN_PRIORITIZER_PROVIDER_UPDATE_API_TOKEN") or None,
        once=_bool(values.get("VULN_PRIORITIZER_PROVIDER_UPDATE_ONCE"), default=False),
    )


def run_scheduler(
    config: ProviderSchedulerConfig,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    while True:
        response = trigger_provider_update(config)
        print(
            "provider update job submitted: "
            f"id={response.get('id')} status={response.get('status')} "
            f"snapshot={response.get('metadata', {}).get('new_snapshot_id')}",
            flush=True,
        )
        if config.once:
            return
        sleep(config.interval_seconds)


def trigger_provider_update(config: ProviderSchedulerConfig) -> dict[str, Any]:
    request = build_provider_update_request(config)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw_detail = exc.read()
        detail = (
            raw_detail.decode("utf-8", errors="replace")
            if isinstance(raw_detail, bytes)
            else str(raw_detail)
        )
        if exc.code == 409:
            return {
                "id": None,
                "status": "blocked",
                "metadata": {
                    "http_status": exc.code,
                    "detail": detail,
                },
            }
        raise RuntimeError(f"provider update request failed: {exc.code} {detail}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("provider update response was not a JSON object")
    return payload


def build_provider_update_request(config: ProviderSchedulerConfig) -> urllib.request.Request:
    body: dict[str, Any] = {
        "sources": list(config.sources),
        "cache_only": config.cache_only,
    }
    if config.max_cves is not None:
        body["max_cves"] = config.max_cves
    headers = {"Content-Type": "application/json"}
    if config.api_token:
        headers["X-API-Token"] = config.api_token
    return urllib.request.Request(
        f"{config.base_url.rstrip('/')}/api/providers/update-jobs",
        data=json.dumps(body, sort_keys=True).encode("utf-8"),
        headers=headers,
        method="POST",
    )


def _sources(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return DEFAULT_SOURCES
    values = tuple(value.strip() for value in raw.split(",") if value.strip())
    invalid = sorted(set(values) - {"nvd", "epss", "kev"})
    if invalid:
        raise ValueError("Unsupported provider source(s): " + ", ".join(invalid))
    return values or DEFAULT_SOURCES


def _bool(raw: str | None, *, default: bool) -> bool:
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Expected boolean value, got {raw!r}")


def _positive_int(raw: str | None, default: int, name: str) -> int:
    value = _optional_positive_int(raw, name)
    return default if value is None else value


def _optional_positive_int(raw: str | None, name: str) -> int | None:
    if raw is None or not raw.strip():
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def main() -> None:
    run_scheduler(load_scheduler_config())


if __name__ == "__main__":
    main()
