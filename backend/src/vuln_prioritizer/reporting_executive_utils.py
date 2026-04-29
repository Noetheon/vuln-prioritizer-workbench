"""Low-level executive report formatting utilities."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from vuln_prioritizer.scoring import determine_cvss_only_priority


def _score(value: Any, *, digits: int) -> str:
    number = _float_value(value)
    if number < 0:
        return "N.A."
    return f"{number:.{digits}f}"


def _priority_label(finding: dict[str, Any]) -> str:
    return _text(finding.get("priority_label") or finding.get("priority"), default="Low")


def _attack_label(finding: dict[str, Any]) -> str:
    relevance = _text(finding.get("attack_relevance"), default="Unmapped")
    if finding.get("attack_mapped"):
        return f"ATT&CK {relevance}"
    return relevance


def _baseline_delta_label(finding: dict[str, Any]) -> str:
    cvss = _float_value(finding.get("cvss_base_score"))
    cvss_value = None if cvss < 0 else cvss
    _, cvss_rank = determine_cvss_only_priority(cvss_value)
    priority_rank = _int_value(finding.get("priority_rank")) or cvss_rank
    delta = cvss_rank - priority_rank
    if delta > 0:
        return f"Raised by {delta}"
    if delta < 0:
        return f"Lowered by {abs(delta)}"
    return "No change"


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int_value(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _positive_int(value: Any) -> int:
    number = _int_value(value)
    return number if number > 0 else 0


def _float_value(value: Any) -> float:
    if isinstance(value, bool) or value is None:
        return -1.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return -1.0
    if math.isnan(number) or math.isinf(number):
        return -1.0
    return number


def _pct(value: int, total: int) -> int:
    if total <= 0:
        return 0
    return max(0, min(100, round((value / total) * 100)))


def _text(value: Any, *, default: str = "not supplied") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _basename(value: Any) -> str:
    text = _text(value, default="")
    if not text:
        return ""
    return text.replace("\\", "/").rsplit("/", 1)[-1]


def _report_period(metadata: dict[str, Any], generated_at: str) -> str:
    sources = metadata.get("input_sources")
    if isinstance(sources, list) and len(sources) > 1:
        return f"{len(sources)} input sources"
    return generated_at


def _format_report_timestamp(value: Any) -> str:
    text = _text(value, default="not available")
    if text in {"", "not available"}:
        return "not available"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text

    date_label = f"{parsed.strftime('%b')} {parsed.day}, {parsed.year}"
    time_label = parsed.strftime("%H:%M")
    zone_label = parsed.tzname() or ""
    return f"{date_label} {time_label} {zone_label}".strip()


def _list_first(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            text = _text(item, default="")
            if text:
                return text
    return ""


def _list_values(value: Any, *, limit: int = 5) -> list[str]:
    if not isinstance(value, list):
        return []
    values: list[str] = []
    for item in value:
        text = _text(item, default="")
        if text and text not in values:
            values.append(text)
        if len(values) >= limit:
            break
    return values


def _provider_value(provider_snapshot: Any | None, attr_name: str) -> str:
    if provider_snapshot is None:
        return "not available"
    return _text(getattr(provider_snapshot, attr_name, None), default="not available")


def _short_provider_date(value: str) -> str:
    if not value or value == "not available":
        return "not available"
    if "T" in value:
        date_part, time_part = value.split("T", 1)
        return f"{date_part} {time_part[:5]}"
    return value


def _attr(value: Any, name: str) -> str:
    return _text(getattr(value, name, None), default="")


def _sha_preview(value: str) -> str:
    return value[:10] if value else "no checksum"


def _truncate(value: str, limit: int) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."
