"""Provider update service constants."""

from __future__ import annotations

PROVIDER_UPDATE_INPUT_TYPE = "provider_update"

PROVIDER_UPDATE_PROJECT_NAME = "Provider Updates"

PROVIDER_UPDATE_LOCK_FILE = ".workbench-provider-update.lock"

PROVIDER_UPDATE_LOCK_STALE_SECONDS = 6 * 60 * 60

VALID_PROVIDER_SOURCES = ("nvd", "epss", "kev")


__all__ = [
    "PROVIDER_UPDATE_INPUT_TYPE",
    "PROVIDER_UPDATE_PROJECT_NAME",
    "PROVIDER_UPDATE_LOCK_FILE",
    "PROVIDER_UPDATE_LOCK_STALE_SECONDS",
    "VALID_PROVIDER_SOURCES",
]
