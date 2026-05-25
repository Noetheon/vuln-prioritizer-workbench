"""Shared classification, formatting, and list helpers for executive HTML reports."""

from __future__ import annotations

import html
import re
from collections import Counter
from collections.abc import Callable
from datetime import datetime

from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import _priority_label


def render_safe_text_with_links(text: str | None) -> str:
    """Escape HTML characters and format safe markdown-style links."""
    if not text:
        return "N/A"

    def escape_preserve_spaces(val: str) -> str:
        """Escape preserve spaces function."""
        return html.escape(re.sub(r"\s+", " ", val), quote=True)

    pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
    last_idx = 0
    parts = []

    for match in pattern.finditer(text):
        before = text[last_idx : match.start()]
        parts.append(escape_preserve_spaces(before))

        label = match.group(1)
        url = match.group(2)

        clean_url = url.strip().lower()
        if (clean_url.startswith("http://") or clean_url.startswith("https://")) and not any(
            c in clean_url for c in "\r\n\t\"'"
        ):
            safe_url = html.escape(url.strip(), quote=True)
            safe_label = escape_preserve_spaces(label)
            parts.append(
                f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer">{safe_label}</a>'
            )
        else:
            parts.append(escape_preserve_spaces(match.group(0)))

        last_idx = match.end()

    parts.append(escape_preserve_spaces(text[last_idx:]))
    return "".join(parts)


def _is_overdue_helper(date_str: str | None, ref_date: datetime) -> bool:
    """Is overdue helper function."""
    if not date_str:
        return False
    try:
        dt = datetime.strptime(date_str.split("T")[0], "%Y-%m-%d")
        return dt.date() < ref_date.date()
    except ValueError:
        return False


def _finding_sort_key(finding: MarkdownReportFinding) -> tuple[int, int, str]:
    """Finding sort key function."""
    return (
        int(finding.operational_rank or 999_999),
        int(finding.priority_rank or 999_999),
        finding.cve_id,
    )


def _status_value(finding: MarkdownReportFinding) -> str:
    """Status value function."""
    return str(finding.status or "").split(".", maxsplit=1)[-1].strip().lower()


def _is_under_investigation_finding(finding: MarkdownReportFinding) -> bool:
    """Is under investigation finding function."""
    if finding.under_investigation:
        return True
    status_counts = finding.explanation.get("vex_statuses")
    if isinstance(status_counts, dict) and "under_investigation" in status_counts:
        return True
    status = finding.explanation.get("vex_status")
    return isinstance(status, str) and status.strip().lower() == "under_investigation"


def _is_fixed_evidence_finding(finding: MarkdownReportFinding) -> bool:
    """Is fixed evidence finding function."""
    return _status_value(finding) == "fixed"


def _is_actionable_finding(finding: MarkdownReportFinding) -> bool:
    """Is actionable finding function."""
    return _finding_actionability_bucket(finding) == "open"


def _is_suppressed_finding(finding: MarkdownReportFinding) -> bool:
    """Is suppressed finding function."""
    status = str(finding.status or "").split(".", maxsplit=1)[-1].strip().lower()
    return finding.suppressed_by_vex or status == "suppressed"


def _is_accepted_risk_finding(finding: MarkdownReportFinding) -> bool:
    """Is accepted risk finding function."""
    status = _status_value(finding)
    return finding.waived or status == "accepted"


def _has_governance_exception(finding: MarkdownReportFinding) -> bool:
    """Has governance exception function."""
    return (
        _is_accepted_risk_finding(finding)
        or _is_suppressed_finding(finding)
        or _is_fixed_evidence_finding(finding)
        or _is_under_investigation_finding(finding)
    )


def _occurrence_count(finding: MarkdownReportFinding) -> int:
    """Occurrence count function."""
    return max(1, len(finding.occurrences))


def _count_findings(
    findings: list[MarkdownReportFinding],
    predicate: Callable[[MarkdownReportFinding], bool],
) -> int:
    """Count findings function."""
    return sum(1 for finding in findings if predicate(finding))


def _unique_values(
    findings: list[MarkdownReportFinding],
    value_for_finding: Callable[[MarkdownReportFinding], str | None],
) -> list[str]:
    """Unique values function."""
    values = {
        value.strip()
        for finding in findings
        if (value := value_for_finding(finding)) is not None and value.strip()
    }
    return sorted(values)


def _pluralize(count: int, singular: str, plural: str | None = None) -> str:
    """Pluralize function."""
    label = singular if count == 1 else plural or f"{singular}s"
    return f"{count} {label}"


def _normalized_context_label(value: str) -> str:
    """Normalized context label function."""
    normalized = value.strip().lower().replace("_", "-")
    replacements = {
        "prod": "production",
        "internet-facing": "internet facing",
        "external": "external",
        "dmz": "DMZ",
        "dr": "DR",
    }
    return replacements.get(normalized, normalized.replace("-", " "))


def _joined_context(values: list[str], *, limit: int = 3, noun: str = "value") -> str:
    """Joined context function."""
    normalized = [_normalized_context_label(value) for value in values if value]
    return _short_list(sorted(set(normalized)), limit=limit, noun=noun) if normalized else "Unknown"


def _short_list(values: list[str], *, limit: int = 3, noun: str = "item") -> str:
    """Short list function."""
    if not values:
        return "N/A"
    shown = values[:limit]
    if len(values) <= limit:
        return ", ".join(shown)
    hidden_count = len(values) - limit
    noun_text = noun if hidden_count == 1 else f"{noun}s"
    return ", ".join(shown) + f", and {hidden_count} additional {noun_text}"


def _counted_or_full_list(values: list[str], *, noun: str) -> str:
    """Counted or full list function."""
    unique_values = sorted({value for value in values if value})
    if not unique_values:
        return "N/A"
    noun_text = noun if len(unique_values) == 1 else f"{noun}s"
    return f"{len(unique_values)} {noun_text}: {', '.join(unique_values)}"


def _actionable_findings(findings: list[MarkdownReportFinding]) -> list[MarkdownReportFinding]:
    """Actionable findings function."""
    return [finding for finding in findings if _is_actionable_finding(finding)]


def _finding_actionability_bucket(finding: MarkdownReportFinding) -> str:
    """Finding actionability bucket function."""
    if _is_fixed_evidence_finding(finding):
        return "fixed"
    if _is_accepted_risk_finding(finding):
        return "accepted"
    if _is_under_investigation_finding(finding):
        return "open"
    if _is_suppressed_finding(finding):
        return "suppressed"
    return "open"


def _actionability_counts_helper(
    findings: list[MarkdownReportFinding],
) -> Counter[str]:
    """Actionability counts helper function."""
    counts: Counter[str] = Counter()
    for finding in findings:
        counts[_finding_actionability_bucket(finding)] += 1
    return counts


def _actionability_summary_helper(findings: list[MarkdownReportFinding]) -> str:
    """Actionability summary helper function."""
    counts = _actionability_counts_helper(findings)
    parts = []
    for bucket in ("open", "accepted", "suppressed", "fixed"):
        count = counts.get(bucket, 0)
        if count:
            parts.append(f"{count} {bucket}")
    return ", ".join(parts) if parts else "No findings"


def _severity_open_count(findings: list[MarkdownReportFinding], severity: str) -> int:
    """Severity open count function."""
    return _count_findings(
        findings,
        lambda finding: (
            _priority_label(finding.priority) == severity and _is_actionable_finding(finding)
        ),
    )


def _fixed_finding_count(findings: list[MarkdownReportFinding]) -> int:
    """Fixed finding count function."""
    return _count_findings(
        findings,
        lambda finding: _finding_actionability_bucket(finding) == "fixed",
    )


__all__ = [
    "render_safe_text_with_links",
    "_is_overdue_helper",
    "_finding_sort_key",
    "_status_value",
    "_is_under_investigation_finding",
    "_is_fixed_evidence_finding",
    "_is_actionable_finding",
    "_is_suppressed_finding",
    "_is_accepted_risk_finding",
    "_has_governance_exception",
    "_occurrence_count",
    "_count_findings",
    "_unique_values",
    "_pluralize",
    "_normalized_context_label",
    "_joined_context",
    "_short_list",
    "_counted_or_full_list",
    "_actionable_findings",
    "_finding_actionability_bucket",
    "_actionability_counts_helper",
    "_actionability_summary_helper",
    "_severity_open_count",
    "_fixed_finding_count",
]
