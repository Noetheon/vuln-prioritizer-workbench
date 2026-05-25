"""Evidence package rows derived from prepared bundle artifact entries."""

from __future__ import annotations

from typing import Any

from app.services.report_contracts import (
    REPORT_FILENAME_ATTACK_NAVIGATOR,
    REPORT_FILENAME_FINDINGS_CSV,
    REPORT_FILENAME_GOVERNANCE_ASSET_CONTEXT,
    REPORT_FILENAME_GOVERNANCE_DETECTION_COVERAGE,
    REPORT_FILENAME_GOVERNANCE_ROLLUPS,
    REPORT_FILENAME_GOVERNANCE_VEX,
    REPORT_FILENAME_GOVERNANCE_WAIVERS,
    REPORT_FILENAME_SARIF_RESULTS,
)
from app.services.report_models import EvidencePackageArtifact, EvidencePackageContext

_PURPOSES = {
    "manifest.json": "Bundle manifest and artifact hash verification.",
    "executive.html": "Decision oriented executive brief.",
    "technical.md": "Detailed analyst handoff with finding rows and rationale.",
    "analysis.json": "Machine readable analysis export.",
    REPORT_FILENAME_FINDINGS_CSV: "Spreadsheet review of findings and owner scope.",
    REPORT_FILENAME_SARIF_RESULTS: "SARIF 2.1.0 integration output.",
    "provider-snapshot.json": "Provider snapshot replay for reproducibility.",
    REPORT_FILENAME_ATTACK_NAVIGATOR: "Defensive ATT&CK Navigator layer for mapped findings.",
    REPORT_FILENAME_GOVERNANCE_ROLLUPS: "Governance rollups for owners, services and assets.",
    REPORT_FILENAME_GOVERNANCE_WAIVERS: "Accepted risk and waiver evidence.",
    REPORT_FILENAME_GOVERNANCE_VEX: "VEX status summary evidence.",
    REPORT_FILENAME_GOVERNANCE_ASSET_CONTEXT: "Asset context evidence.",
    REPORT_FILENAME_GOVERNANCE_DETECTION_COVERAGE: "Detection coverage governance evidence.",
}


def evidence_package_context_from_entries(
    file_entries: list[dict[str, Any]],
    *,
    has_governance: bool,
    has_attack_layer: bool,
) -> EvidencePackageContext:
    """Build bundle-aware evidence rows before executive.html is rendered."""
    entries_by_path = {entry["path"]: entry for entry in file_entries}
    artifacts = [
        EvidencePackageArtifact(
            artifact="manifest.json",
            purpose=_PURPOSES["manifest.json"],
            status="included",
            note="Generated after artifact hashes are finalized.",
        ),
        EvidencePackageArtifact(
            artifact="executive.html",
            purpose=_PURPOSES["executive.html"],
            status="included",
            note="Hash recorded in final manifest.json after this HTML is rendered.",
        ),
    ]
    for path in _ORDERED_OPTIONAL_PATHS:
        entry = entries_by_path.get(path)
        if entry is not None:
            artifacts.append(_artifact_from_entry(path, entry))
        elif path == REPORT_FILENAME_ATTACK_NAVIGATOR and not has_attack_layer:
            artifacts.append(
                EvidencePackageArtifact(
                    artifact=path,
                    purpose=_PURPOSES[path],
                    status="optional",
                    note="Generated only when reviewed ATT&CK mappings are available.",
                )
            )
    if not has_governance:
        artifacts.append(
            EvidencePackageArtifact(
                artifact="governance/*.json",
                purpose="Accepted risk, VEX and asset context evidence.",
                status="optional",
                note="Generated only when governance artifacts are available.",
            )
        )
    return EvidencePackageContext(mode="bundle", artifacts=artifacts)


def _artifact_from_entry(path: str, entry: dict[str, Any]) -> EvidencePackageArtifact:
    return EvidencePackageArtifact(
        artifact=path,
        purpose=_PURPOSES.get(path, "Evidence bundle artifact."),
        status="included",
        sha256=entry["sha256"],
        size_bytes=int(entry["size_bytes"]),
        kind=entry["kind"],
    )


_ORDERED_OPTIONAL_PATHS = [
    "technical.md",
    "analysis.json",
    REPORT_FILENAME_FINDINGS_CSV,
    REPORT_FILENAME_SARIF_RESULTS,
    "provider-snapshot.json",
    REPORT_FILENAME_ATTACK_NAVIGATOR,
    REPORT_FILENAME_GOVERNANCE_ROLLUPS,
    REPORT_FILENAME_GOVERNANCE_WAIVERS,
    REPORT_FILENAME_GOVERNANCE_VEX,
    REPORT_FILENAME_GOVERNANCE_ASSET_CONTEXT,
    REPORT_FILENAME_GOVERNANCE_DETECTION_COVERAGE,
]

__all__ = ["evidence_package_context_from_entries"]
