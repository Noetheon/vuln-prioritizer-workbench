"""ATT&CK context helpers for executive HTML reports."""

from __future__ import annotations

from typing import Any

from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_common import _short_list
from app.services.report_models import MarkdownReportFinding
from app.services.report_renderer_common import _boolish_signal, _list_value

REVIEWED_ATTACK_SOURCES = {
    "ctid-json",
    "ctid",
    "ctid-mappings-explorer",
    "local-curated",
    "curated",
    "imported-reviewed",
}


def _technique_ids_for_findings(findings: list[MarkdownReportFinding]) -> list[str]:
    """Technique ids for findings function."""
    technique_ids: set[str] = set()
    for finding in findings:
        if not _boolish_signal(finding, "attack_mapped"):
            continue
        for value in _list_value(finding.explanation, "attack_techniques"):
            if isinstance(value, str) and value.strip():
                technique_ids.add(value.strip())
            elif isinstance(value, dict):
                candidate = value.get("technique_id") or value.get("attack_object_id")
                if isinstance(candidate, str) and candidate.strip():
                    technique_ids.add(candidate.strip())
        for key in ("attack_context", "attack"):
            value = finding.explanation.get(key)
            if not isinstance(value, dict):
                continue
            for nested in _list_value(value, "techniques"):
                if isinstance(nested, dict):
                    candidate = nested.get("technique_id") or nested.get("attack_object_id")
                    if isinstance(candidate, str) and candidate.strip():
                        technique_ids.add(candidate.strip())
                elif isinstance(nested, str) and nested.strip():
                    technique_ids.add(nested.strip())
    return sorted(technique_ids)


def _attack_context_value(finding: MarkdownReportFinding) -> dict[str, Any]:
    """Attack context value function."""
    value = finding.explanation.get("attack_context")
    return dict(value) if isinstance(value, dict) else {}


def _is_reviewed_attack_context(finding: MarkdownReportFinding) -> bool:
    """Is reviewed attack context function."""
    context = _attack_context_value(finding)
    source = str(context.get("source") or "").strip().lower()
    review_status = str(context.get("review_status") or "").strip().lower()
    return (
        bool(context.get("mapped"))
        and source in REVIEWED_ATTACK_SOURCES
        and review_status == "reviewed"
    )


def _reviewed_attack_mapping_rows_for_findings(
    findings: list[MarkdownReportFinding],
) -> list[dict[str, str]]:
    """Reviewed attack mapping rows for findings function."""
    rows: dict[tuple[str, str], dict[str, str]] = {}
    for finding in findings:
        if not _is_reviewed_attack_context(finding):
            continue
        context = _attack_context_value(finding)
        source = str(context.get("source") or "reviewed mapping")
        mappings = _list_value(context, "mappings")
        technique_ids = _list_value(context, "technique_ids")
        if not mappings and technique_ids:
            mappings = [{"technique_id": technique_id} for technique_id in technique_ids]
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            technique_id = (
                mapping.get("technique_id") or mapping.get("attack_object_id") or mapping.get("id")
            )
            if not isinstance(technique_id, str) or not technique_id.strip():
                continue
            name = mapping.get("technique_name") or mapping.get("attack_object_name") or ""
            key = (technique_id.strip(), source)
            rows[key] = {
                "technique_id": technique_id.strip(),
                "name": str(name).strip(),
                "source": source,
            }
    return [rows[key] for key in sorted(rows)]


def _reviewed_attack_technique_ids_for_findings(
    findings: list[MarkdownReportFinding],
) -> list[str]:
    """Reviewed attack technique ids for findings function."""
    return [row["technique_id"] for row in _reviewed_attack_mapping_rows_for_findings(findings)]


def _html_attack_context_table_helper(findings: list[MarkdownReportFinding]) -> str:
    """Html attack context table helper function."""
    reviewed_mappings = _reviewed_attack_mapping_rows_for_findings(findings)
    mapped_count = sum(1 for finding in findings if _is_reviewed_attack_context(finding))
    raw_mapped_count = sum(1 for finding in findings if _boolish_signal(finding, "attack_mapped"))
    needs_source_review = max(0, raw_mapped_count - mapped_count)
    unmapped_count = len(findings) - mapped_count
    navigator_layer_status = (
        "Included in Evidence ZIP" if mapped_count > 0 else "Optional / not generated"
    )
    technique_ids = [row["technique_id"] for row in reviewed_mappings]
    mapping_sources = sorted({row["source"] for row in reviewed_mappings if row["source"]})
    technique_status = (
        _short_list(technique_ids, limit=6, noun="technique")
        if technique_ids
        else "No reviewed techniques recorded."
    )
    attack_rows = [
        ("Mapped findings", f"{mapped_count} reviewed mapping records available."),
        ("Common techniques", technique_status),
        (
            "Mapping source",
            _short_list(mapping_sources, limit=4, noun="source")
            if mapping_sources
            else "No reviewed mapping source recorded.",
        ),
        ("Navigator layer", navigator_layer_status),
        (
            "Mappings needing source review",
            f"{needs_source_review} mapping records are not shown as confirmed.",
        ),
        ("Unmapped CVEs", f"{unmapped_count} remain unmapped. No LLM inferred mappings are used."),
    ]
    attack_rows_html = []
    for context, status in attack_rows:
        attack_rows_html.append(
            f"<tr><td><strong>{_safe_html(context)}</strong></td><td>{_safe_html(status)}</td></tr>"
        )

    return (
        "      <div class='note-box'>\n"
        "        <p>ATT&amp;CK context is shown as reviewed defensive context only. "
        "It supports SOC validation and telemetry review, but it does not prove "
        "compromise and does not override the transparent base priority from CVSS, "
        "EPSS, KEV and asset context.</p>\n"
        "      </div>\n"
        "      <div class='table-wrap'>\n"
        "        <table class='compact-table'>\n"
        "          <thead>\n"
        "            <tr><th>Context</th><th>Status</th></tr>\n"
        "          </thead>\n"
        "          <tbody>\n"
        f"            {chr(10).join(attack_rows_html)}\n"
        "          </tbody>\n"
        "        </table>\n"
        "      </div>"
    )


__all__ = [
    "REVIEWED_ATTACK_SOURCES",
    "_technique_ids_for_findings",
    "_attack_context_value",
    "_is_reviewed_attack_context",
    "_reviewed_attack_mapping_rows_for_findings",
    "_reviewed_attack_technique_ids_for_findings",
    "_html_attack_context_table_helper",
]
