"""Shared model helpers."""

from datetime import UTC, datetime


def get_datetime_utc() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)
