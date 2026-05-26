"""Evidence package inventory helpers for executive HTML reports."""

from __future__ import annotations

from app.services.report_formatting import safe_html as _safe_html
from app.services.report_models import EvidencePackageContext, EvidencePackageRow


def _html_evidence_package_table_helper(
    *,
    has_attack_layer: bool,
    has_governance: bool,
    evidence_package_context: EvidencePackageContext | None = None,
) -> str:
    """Html evidence package table helper function."""
    evidence_package_rows = _evidence_package_rows_helper(
        has_attack_layer=has_attack_layer,
        has_governance=has_governance,
        evidence_package_context=evidence_package_context,
    )
    evidence_package_rows_html = []
    for row in evidence_package_rows:
        status = row.status
        if status == "included":
            badge_class = "badge-success"
        elif status == "expected":
            badge_class = "badge-info"
        else:
            badge_class = "badge-neutral"
        included_badge = f"<span class='badge {badge_class}'>{_safe_html(status)}</span>"
        sha256 = row.sha256 or "N/A"
        size_or_note = (
            f"{int(row.size_bytes):,} bytes" if row.size_bytes is not None else row.note or "N/A"
        )
        evidence_package_rows_html.append(
            f"<tr><td><code>{_safe_html(row.artifact)}</code></td>"
            f"<td>{_safe_html(row.purpose)}</td><td>{included_badge}</td>"
            f"<td><code>{_safe_html(sha256)}</code></td>"
            f"<td>{_safe_html(size_or_note)}</td></tr>"
        )

    return (
        "      <div class='table-wrap'>\n"
        "        <table class='compact-table evidence-package-table'>\n"
        "          <thead>\n"
        "            <tr><th>Artifact File</th><th>Purpose</th><th>Status</th>"
        "<th>SHA256</th><th>Size / Note</th></tr>\n"
        "          </thead>\n"
        "          <tbody>\n"
        f"            {chr(10).join(evidence_package_rows_html)}\n"
        "          </tbody>\n"
        "        </table>\n"
        "      </div>"
    )


def _evidence_package_rows_helper(
    *,
    has_attack_layer: bool,
    has_governance: bool,
    evidence_package_context: EvidencePackageContext | None = None,
) -> list[EvidencePackageRow]:
    """Evidence package rows helper function."""
    if evidence_package_context is not None and evidence_package_context.artifacts:
        return [
            EvidencePackageRow(
                artifact=artifact.artifact,
                purpose=artifact.purpose,
                status=artifact.status,
                sha256=artifact.sha256,
                size_bytes=artifact.size_bytes,
                kind=artifact.kind,
                note=artifact.note,
            )
            for artifact in evidence_package_context.artifacts
        ]
    base_status = "expected"
    base_note = "Expected when Evidence ZIP is generated."
    return [
        EvidencePackageRow(
            artifact="manifest.json",
            purpose="Bundle manifest and artifact hash verification.",
            status=base_status,
            note=base_note,
        ),
        EvidencePackageRow(
            artifact="executive.html",
            purpose="Decision oriented executive brief.",
            status=base_status,
            note=base_note,
        ),
        EvidencePackageRow(
            artifact="technical.md",
            purpose="Detailed analyst handoff with finding rows and rationale.",
            status=base_status,
            note=base_note,
        ),
        EvidencePackageRow(
            artifact="analysis.json",
            purpose="Machine readable analysis export.",
            status=base_status,
            note=base_note,
        ),
        EvidencePackageRow(
            artifact="findings.csv",
            purpose="Spreadsheet review of findings and owner scope.",
            status=base_status,
            note=base_note,
        ),
        EvidencePackageRow(
            artifact="results.sarif",
            purpose="SARIF 2.1.0 integration output.",
            status=base_status,
            note=base_note,
        ),
        EvidencePackageRow(
            artifact="provider-snapshot.json",
            purpose="Provider snapshot replay for reproducibility.",
            status=base_status,
            note=base_note,
        ),
        EvidencePackageRow(
            artifact="attack-navigator-layer.json",
            purpose="Defensive ATT&CK Navigator layer for mapped findings.",
            status="included" if has_attack_layer else "optional",
            note="Generated only when reviewed ATT&CK mappings are available.",
        ),
        EvidencePackageRow(
            artifact="governance/*.json",
            purpose="Accepted risk, VEX and asset context evidence.",
            status="included" if has_governance else "optional",
            note="Generated only when governance artifacts are available.",
        ),
    ]


def _evidence_bundle_status_label(
    evidence_package_context: EvidencePackageContext | None,
) -> str:
    """Evidence bundle status label function."""
    return (
        "Ready"
        if evidence_package_context is not None and evidence_package_context.mode == "bundle"
        else "Expected"
    )


__all__ = [
    "_html_evidence_package_table_helper",
    "_evidence_package_rows_helper",
    "_evidence_bundle_status_label",
]
