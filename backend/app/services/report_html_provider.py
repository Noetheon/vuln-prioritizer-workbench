"""Provider snapshot HTML helpers."""

from __future__ import annotations

from datetime import datetime

from app.services.report_html_helpers import (
    _html_provider_snapshot_helper,
    _provider_freshness_rows_helper,
    _provider_freshness_status_helper,
)
from app.services.report_models import MarkdownProviderSnapshot


def _html_provider_snapshot(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
) -> str:
    return _html_provider_snapshot_helper(snapshot, generated_at)


def _provider_freshness_status(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
) -> str:
    return _provider_freshness_status_helper(snapshot, generated_at)


def _provider_freshness_rows(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
) -> list[dict[str, str]]:
    return _provider_freshness_rows_helper(snapshot, generated_at)


__all__ = [
    "_html_provider_snapshot",
    "_provider_freshness_rows",
    "_provider_freshness_status",
]
