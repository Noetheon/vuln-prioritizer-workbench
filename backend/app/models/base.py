"""Shared model helpers."""

import os
from datetime import UTC, datetime


def get_datetime_utc() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    fixed_now = os.getenv("WORKBENCH_FIXED_NOW")
    if fixed_now:
        parsed = datetime.fromisoformat(fixed_now.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return datetime.now(UTC)
