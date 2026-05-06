"""Small formatting helpers shared by Workbench report renderers."""

from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Any

from app.services.report_contracts import MARKDOWN_SPECIAL_CHARS


def safe_cell(value: object | None) -> str:
    """Return a pipe-safe Markdown table cell."""
    return safe_inline(value).replace("|", "\\|")


def safe_inline(value: object | None) -> str:
    """Return a whitespace-normalized Markdown inline value."""
    if value is None:
        return "N/A"
    text = str(value).strip()
    if not text:
        return "N/A"
    text = re.sub(r"\s+", " ", text)
    escaped = html.escape(text, quote=True)
    return "".join(
        f"\\{character}" if character in MARKDOWN_SPECIAL_CHARS else character
        for character in escaped
    )


def safe_html(value: object | None) -> str:
    """Return a whitespace-normalized HTML text node."""
    if value is None:
        return "N/A"
    text = str(value).strip()
    if not text:
        return "N/A"
    return html.escape(re.sub(r"\s+", " ", text), quote=True)


def csv_safe_cell(value: object | None) -> str:
    """Return a CSV cell guarded against spreadsheet formula execution."""
    text = "" if value is None else str(value)
    if text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def format_number(value: float | None) -> str:
    """Format numeric report values without unstable trailing zeroes."""
    if value is None:
        return "N/A"
    number = float(value)
    if number.is_integer():
        return str(int(number))
    return f"{number:.3f}".rstrip("0").rstrip(".")


def iso_datetime(value: datetime) -> str:
    """Return the report JSON timestamp form."""
    return value.isoformat().replace("+00:00", "Z")


def metadata_bool(metadata: dict[str, Any], key: str) -> str:
    """Render a provider metadata bool for Markdown reports."""
    if key not in metadata:
        return "N/A"
    return "Yes" if bool(metadata[key]) else "No"


def metadata_list(metadata: dict[str, Any], key: str) -> str:
    """Render a provider metadata list for Markdown reports."""
    value = metadata.get(key)
    if isinstance(value, list):
        items = [str(item) for item in value if item]
        return ", ".join(items) if items else "N/A"
    return str(value) if value else "N/A"


def dict_value(value: Any) -> dict[str, Any]:
    """Return a shallow dict for JSON-like mapping values."""
    return dict(value) if isinstance(value, dict) else {}
