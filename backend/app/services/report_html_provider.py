"""Provider snapshot HTML helpers."""

from __future__ import annotations

from app.services.report_formatting import metadata_bool as _metadata_bool
from app.services.report_formatting import metadata_list as _metadata_list
from app.services.report_formatting import safe_html as _safe_html
from app.services.report_models import MarkdownProviderSnapshot


def _html_provider_snapshot(snapshot: MarkdownProviderSnapshot | None) -> str:
    if snapshot is None:
        return "<p>No provider snapshot was linked to this analysis run.</p>"

    selected_sources = _metadata_list(snapshot.source_metadata, "selected_sources")
    locked_provider_data = _metadata_bool(snapshot.source_metadata, "locked_provider_data")
    cells = [
        ("Snapshot ID", snapshot.id),
        ("Content Hash", snapshot.content_hash),
        ("NVD Last Sync", snapshot.nvd_last_sync),
        ("EPSS Date", snapshot.epss_date),
        ("KEV Catalog Version", snapshot.kev_catalog_version),
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
    return f'      <dl class="provider-grid">\n{items}\n      </dl>'


__all__ = ["_html_provider_snapshot"]
