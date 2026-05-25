"""Provider freshness helpers for executive HTML reports."""

from __future__ import annotations

from datetime import UTC, datetime

from app.services.report_formatting import safe_html as _safe_html
from app.services.report_models import EvidencePackageContext, MarkdownProviderSnapshot

PROVIDER_FRESHNESS_THRESHOLDS = {
    "epss": {"warning_days": 7, "stale_days": 30},
    "nvd": {"stale_days": 30},
    "kev": {"stale_days": 30},
}


def _calculate_age_and_verdict_helper(
    date_str: str | None,
    generated_at: datetime | None,
    *,
    source: str = "epss",
) -> tuple[str, str, str]:
    """Calculate age and verdict helper function."""
    thresholds = PROVIDER_FRESHNESS_THRESHOLDS.get(
        source,
        PROVIDER_FRESHNESS_THRESHOLDS["epss"],
    )
    if not date_str or not generated_at:
        return "N/A", "Unknown", "badge-neutral"
    try:
        clean_date_str = date_str.split("T")[0]
        dt = datetime.strptime(clean_date_str, "%Y-%m-%d")
        report_dt = generated_at.astimezone(UTC) if generated_at.tzinfo else generated_at
        delta = (report_dt.date() - dt.date()).days
        if delta < 0:
            delta = 0
        age_str = f"{delta} day{'s' if delta != 1 else ''}"
        stale_days = int(thresholds["stale_days"])
        warning_days = thresholds.get("warning_days")
        if warning_days is not None and delta > int(warning_days) and delta <= stale_days:
            return age_str, "Warning", "badge-warning"
        if delta > stale_days:
            return age_str, "Stale", "badge-stale"
        return age_str, "Fresh", "badge-success"
    except ValueError:
        if source == "kev" and date_str:
            return "N/A", "Needs Review", "badge-warning"
        return "N/A", "Unknown", "badge-neutral"


def _provider_status_class(status: str) -> str:
    """Provider status class function."""
    return {
        "Fresh": "badge-success",
        "Warning": "badge-warning",
        "Stale": "badge-stale",
        "Reproducible": "badge-success",
        "Included": "badge-success",
        "Expected": "badge-info",
        "Recorded": "badge-success",
        "Controlled": "badge-success",
        "Needs Review": "badge-warning",
        "Not available": "badge-neutral",
        "Unknown": "badge-neutral",
    }.get(status, "badge-neutral")


def _evidence_bundle_manifest_row_helper(
    evidence_package_context: EvidencePackageContext | None,
) -> dict[str, str]:
    """Evidence bundle manifest row helper function."""
    if evidence_package_context is not None and evidence_package_context.mode == "bundle":
        return {
            "signal": "Evidence bundle manifest",
            "value": evidence_package_context.manifest_path,
            "status": "Included",
            "meaning": (
                "Evidence package rows are derived from the generated bundle artifact list; "
                "the final manifest records artifact hashes."
            ),
        }
    return {
        "signal": "Evidence bundle manifest",
        "value": "manifest.json",
        "status": "Expected",
        "meaning": (
            "Standalone HTML shows expected bundle contents. Generate the Evidence ZIP "
            "to record final manifest hashes."
        ),
    }


def _provider_freshness_rows_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
    evidence_package_context: EvidencePackageContext | None = None,
) -> list[dict[str, str]]:
    """Provider freshness rows helper function."""
    from app.services.report_formatting import metadata_bool as _metadata_bool
    from app.services.report_formatting import metadata_list as _metadata_list

    if snapshot is None:
        return [
            {
                "signal": "Snapshot locked",
                "value": "Not available",
                "status": "Not available",
                "meaning": "No provider snapshot was linked to this analysis run.",
            },
            {
                "signal": "NVD last sync",
                "value": "N/A",
                "status": "Unknown",
                "meaning": "Date is missing; freshness cannot be determined.",
            },
            {
                "signal": "EPSS date",
                "value": "N/A",
                "status": "Unknown",
                "meaning": "Date is missing; freshness cannot be determined.",
            },
            {
                "signal": "KEV catalog version",
                "value": "N/A",
                "status": "Unknown",
                "meaning": "Date is missing; freshness cannot be determined.",
            },
            {
                "signal": "Content hash",
                "value": "Missing",
                "status": "Warning",
                "meaning": "Snapshot hash is missing; bundle verification is weaker.",
            },
            {
                "signal": "Source hashes",
                "value": "N/A",
                "status": "Warning",
                "meaning": "Provider source hashes are missing from this snapshot.",
            },
            {
                "signal": "Selected sources",
                "value": "N/A",
                "status": "Warning",
                "meaning": "Vulnerability intelligence sources were not recorded.",
            },
            {
                "signal": "Static HTML safety",
                "value": "No scripts, no external assets, escaped recommendation text",
                "status": "Controlled",
                "meaning": "Report is suitable for local review and evidence package distribution.",
            },
            _evidence_bundle_manifest_row_helper(evidence_package_context),
        ]

    ref_date = generated_at or datetime.now(UTC)
    locked_provider_data = _metadata_bool(snapshot.source_metadata, "locked_provider_data")

    def dated_row(signal: str, value: str | None, source: str) -> dict[str, str]:
        """Dated row function."""
        age, verdict, _class_name = _calculate_age_and_verdict_helper(
            value,
            ref_date,
            source=source,
        )
        status = verdict
        meaning = (
            f"Source data is {age} old at report generation time."
            if age != "N/A"
            else "Date is missing or invalid, freshness cannot be determined."
        )
        if status == "Stale":
            meaning += " Refresh provider data before formal risk sign-off."
        elif status == "Warning":
            meaning += " Review freshness before executive approval."
        elif status == "Fresh":
            meaning += " Suitable for current operational decision support."
        elif status == "Needs Review":
            meaning = (
                "Stored KEV value is not a clear sync timestamp; verify catalog "
                "version semantics before making a freshness claim."
            )
        return {
            "signal": signal,
            "value": value or "N/A",
            "status": status,
            "meaning": meaning,
        }

    rows = [
        {
            "signal": "Snapshot locked",
            "value": locked_provider_data,
            "status": "Reproducible" if locked_provider_data == "Yes" else "Warning",
            "meaning": (
                "Provider data replay is deterministic for audit and demo. "
                "Note: locked provider data guarantees reproducibility "
                "but does not automatically mean the data is fresh."
                if locked_provider_data == "Yes"
                else "Provider replay lock was not recorded; verify reproducibility."
            ),
        },
        dated_row("NVD last sync", snapshot.nvd_last_sync, "nvd"),
        dated_row("EPSS date", snapshot.epss_date, "epss"),
        dated_row("KEV catalog version", snapshot.kev_catalog_version, "kev"),
        {
            "signal": "Content hash",
            "value": snapshot.content_hash or "Missing",
            "status": "Recorded" if snapshot.content_hash else "Warning",
            "meaning": (
                "Evidence can be verified against the bundle manifest."
                if snapshot.content_hash
                else "Snapshot hash is missing; bundle verification is weaker."
            ),
        },
        {
            "signal": "Source hashes",
            "value": ", ".join(
                f"{key}: {value}" for key, value in sorted(snapshot.source_hashes.items())
            )
            if snapshot.source_hashes
            else "N/A",
            "status": "Recorded" if snapshot.source_hashes else "Warning",
            "meaning": (
                "Provider source hash entries are available for replay comparison."
                if snapshot.source_hashes
                else "Provider source hashes are missing from this snapshot."
            ),
        },
        {
            "signal": "Selected sources",
            "value": _metadata_list(snapshot.source_metadata, "selected_sources"),
            "status": "Recorded"
            if (snapshot.source_metadata and snapshot.source_metadata.get("selected_sources"))
            else "Warning",
            "meaning": "Vulnerability intelligence sources selected for data enrichment.",
        },
        _evidence_bundle_manifest_row_helper(evidence_package_context),
        {
            "signal": "Static HTML safety",
            "value": "No scripts, no external assets, escaped recommendation text",
            "status": "Controlled",
            "meaning": "Report is suitable for local review and evidence package distribution.",
        },
    ]
    return rows


def _provider_freshness_status_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
    evidence_package_context: EvidencePackageContext | None = None,
) -> str:
    """Provider freshness status helper function."""
    rows = _provider_freshness_rows_helper(snapshot, generated_at, evidence_package_context)
    statuses = {row["status"] for row in rows}
    if "Not available" in statuses and len(statuses) == 1:
        return "Not available"
    if "Stale" in statuses:
        return "Stale"
    if {"Warning", "Unknown", "Not available", "Needs Review"} & statuses:
        return "Warning"
    return "Fresh"


def _html_provider_snapshot_helper(
    snapshot: MarkdownProviderSnapshot | None,
    generated_at: datetime | None = None,
    project_name: str | None = None,
    evidence_package_context: EvidencePackageContext | None = None,
) -> str:
    """Html provider snapshot helper function."""
    from app.services.report_formatting import metadata_bool as _metadata_bool
    from app.services.report_formatting import metadata_list as _metadata_list

    _ = project_name

    if snapshot is None:
        freshness_rows = _provider_freshness_rows_helper(
            None,
            generated_at,
            evidence_package_context,
        )
        rows_html = "\n".join(
            f"            <tr>"
            f"<td><strong>{_safe_html(row['signal'])}</strong></td>"
            f"<td>{_safe_html(row['value'])}</td>"
            f"<td><span class='badge {_provider_status_class(row['status'])}'>"
            f"{_safe_html(row['status'])}</span></td>"
            f"<td>{_safe_html(row['meaning'])}</td>"
            f"</tr>"
            for row in freshness_rows
        )
        return (
            "<p>No provider snapshot was linked to this analysis run.</p>\n"
            "      <div class='table-wrap'>\n"
            "        <table>\n"
            "          <thead>\n"
            "            <tr><th>Signal</th><th>Value</th><th>Status</th>"
            "<th>Meaning</th></tr>\n"
            "          </thead>\n"
            f"          <tbody>\n{rows_html}\n          </tbody>\n"
            "        </table>\n"
            "      </div>"
        )

    freshness_rows = _provider_freshness_rows_helper(
        snapshot,
        generated_at,
        evidence_package_context,
    )
    overall_status = _provider_freshness_status_helper(
        snapshot,
        generated_at,
        evidence_package_context,
    )
    rows: list[str] = []
    for row in freshness_rows:
        value = row["value"]
        value_html = (
            f"<code>{_safe_html(value)}</code>"
            if row["signal"] == "Content hash"
            else _safe_html(value)
        )
        status_class = _provider_status_class(row["status"])
        rows.append(
            f"            <tr>"
            f"<td><strong>{_safe_html(row['signal'])}</strong></td>"
            f"<td>{value_html}</td>"
            f"<td><span class='badge {status_class}'>{_safe_html(row['status'])}</span></td>"
            f"<td>{_safe_html(row['meaning'])}</td>"
            f"</tr>"
        )

    alert_text = (
        "Provider data is deterministic evidence for this run. "
        "Refresh stale or warning sources before treating the report as current "
        "external vulnerability intelligence for formal sign-off."
        if overall_status in {"Stale", "Warning"}
        else "Provider data is fresh enough for current operational decision support."
    )

    table_html = (
        "      <div class='verdict-banner'><p><strong>Evidence confidence:</strong> "
        f"{alert_text}</p></div>\n"
        f"      <div class='table-wrap'>\n"
        f"        <table>\n"
        f"          <thead>\n"
        f"            <tr><th>Signal</th><th>Value</th><th>Status</th><th>Meaning</th></tr>\n"
        f"          </thead>\n"
        f"          <tbody>\n"
        f"      {chr(10).join(rows)}\n"
        f"          </tbody>\n"
        f"        </table>\n"
        f"      </div>"
    )

    selected_sources = _metadata_list(snapshot.source_metadata, "selected_sources")
    locked_provider_data = _metadata_bool(snapshot.source_metadata, "locked_provider_data")
    cells = [
        ("Snapshot ID", snapshot.id),
        ("Content Hash", snapshot.content_hash),
        ("Locked Provider Data", locked_provider_data),
        ("Selected Sources", selected_sources),
    ]
    for key, value in sorted(snapshot.source_hashes.items()):
        cells.append((f"Source Hash: {key}", value))
    for key in ("source_path", "item_count", "missing", "validation_error"):
        if key in snapshot.source_metadata:
            cells.append((f"Metadata: {key}", snapshot.source_metadata[key]))

    items = "\n".join(
        f"        <div><dt>{_safe_html(label)}</dt><dd>{_safe_html(value)}</dd></div>"
        for label, value in cells
    )
    return (
        f"{table_html}\n"
        f"      <h3>Raw Provider Metadata</h3>\n"
        f'      <dl class="provider-grid">\n{items}\n      </dl>'
    )


__all__ = [
    "PROVIDER_FRESHNESS_THRESHOLDS",
    "_calculate_age_and_verdict_helper",
    "_provider_status_class",
    "_evidence_bundle_manifest_row_helper",
    "_provider_freshness_rows_helper",
    "_provider_freshness_status_helper",
    "_html_provider_snapshot_helper",
]
