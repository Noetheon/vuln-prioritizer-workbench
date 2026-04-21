"""ATT&CK provider dispatch for legacy CSV and CTID JSON sources."""

from __future__ import annotations

import csv
import re
from pathlib import Path

from vuln_prioritizer.models import AttackData, AttackTechnique
from vuln_prioritizer.providers.attack_metadata import AttackMetadataProvider
from vuln_prioritizer.providers.ctid_mappings import CtidMappingsProvider
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService
from vuln_prioritizer.utils import normalize_cve_id

SEPARATOR_RE = re.compile(r"[;|]")


class AttackProvider:
    """Load ATT&CK context from supported local sources."""

    def __init__(self) -> None:
        self.ctid_provider = CtidMappingsProvider()
        self.metadata_provider = AttackMetadataProvider()
        self.enrichment_service = AttackEnrichmentService()

    def fetch_many(
        self,
        cve_ids: list[str],
        *,
        enabled: bool,
        source: str = "none",
        mapping_file: Path | None = None,
        technique_metadata_file: Path | None = None,
        offline_file: Path | None = None,
    ) -> tuple[dict[str, AttackData], dict[str, str | None], list[str]]:
        if not enabled:
            return {}, _build_metadata(source="none"), []

        if source == "none" and (mapping_file is not None or offline_file is not None):
            candidate = mapping_file or offline_file
            if candidate is not None and candidate.suffix.lower() == ".csv":
                source = "local-csv"
            else:
                source = "ctid-json"
        if source == "none":
            return {}, _build_metadata(source="none"), []

        normalized_source = source
        if offline_file is not None and mapping_file is None:
            mapping_file = offline_file
        if mapping_file is None:
            return (
                {},
                _build_metadata(source=normalized_source),
                ["ATT&CK mode requested, but no ATT&CK mapping file was provided."],
            )

        if normalized_source == "local-csv":
            results, warnings = self._load_legacy_csv(cve_ids, mapping_file)
            warnings.insert(
                0,
                "ATT&CK source local-csv is a legacy compatibility mode; "
                "prefer --attack-source ctid-json for structured CTID-backed ATT&CK context.",
            )
            if technique_metadata_file is not None:
                warnings.append(
                    "ATT&CK technique metadata is ignored when --attack-source local-csv is used."
                )
            enriched = self.enrichment_service.enrich_legacy_csv(cve_ids, attack_data=results)
            return (
                enriched,
                _build_metadata(
                    source="local-csv",
                    mapping_file=mapping_file,
                ),
                warnings,
            )

        if normalized_source == "ctid-json":
            return self._load_ctid_json(
                cve_ids,
                mapping_file=mapping_file,
                technique_metadata_file=technique_metadata_file,
            )

        return (
            {},
            _build_metadata(source=normalized_source),
            [f"Unsupported ATT&CK source: {normalized_source}"],
        )

    def inspect_legacy_csv(
        self,
        mapping_file: Path,
    ) -> tuple[dict[str, AttackData], dict[str, str | None], list[str]]:
        """Load legacy CSV mappings without filtering by requested CVE IDs."""
        results, warnings = self._load_legacy_csv([], mapping_file)
        warnings.insert(
            0,
            "ATT&CK source local-csv is a legacy compatibility mode; "
            "prefer --attack-source ctid-json for structured CTID-backed ATT&CK context.",
        )
        return results, _build_metadata(source="local-csv", mapping_file=mapping_file), warnings

    def _load_ctid_json(
        self,
        cve_ids: list[str],
        *,
        mapping_file: Path,
        technique_metadata_file: Path | None,
    ) -> tuple[dict[str, AttackData], dict[str, str | None], list[str]]:
        mappings_by_cve, mapping_metadata, mapping_warnings = self.ctid_provider.load(mapping_file)
        techniques_by_id: dict[str, AttackTechnique] = {}
        metadata_warnings: list[str] = []
        technique_metadata: dict[str, str | None] = {}

        if technique_metadata_file is not None:
            techniques_by_id, technique_metadata, metadata_warnings = self.metadata_provider.load(
                technique_metadata_file
            )

        results = self.enrichment_service.enrich_ctid(
            cve_ids,
            mappings_by_cve=mappings_by_cve,
            techniques_by_id=techniques_by_id,
            source="ctid-mappings-explorer",
            source_version=(
                mapping_metadata.get("mapping_framework_version")
                or mapping_metadata.get("mapping_version")
            ),
            attack_version=technique_metadata.get("attack_version")
            or mapping_metadata.get("attack_version"),
            domain=technique_metadata.get("domain") or mapping_metadata.get("domain"),
        )
        metadata = _build_metadata(
            source="ctid-mappings-explorer",
            mapping_file=mapping_file,
            technique_metadata_file=technique_metadata_file,
            source_version=mapping_metadata.get("mapping_framework_version")
            or mapping_metadata.get("mapping_version"),
            attack_version=technique_metadata.get("attack_version")
            or mapping_metadata.get("attack_version"),
            domain=technique_metadata.get("domain") or mapping_metadata.get("domain"),
            mapping_framework=mapping_metadata.get("mapping_framework"),
            mapping_framework_version=mapping_metadata.get("mapping_framework_version"),
        )
        return results, metadata, mapping_warnings + metadata_warnings

    def _load_legacy_csv(
        self,
        cve_ids: list[str],
        offline_file: Path,
    ) -> tuple[dict[str, AttackData], list[str]]:
        if not offline_file.exists() or not offline_file.is_file():
            return {}, [f"ATT&CK mapping file not found: {offline_file}"]

        if offline_file.suffix.lower() != ".csv":
            return {}, ["ATT&CK mapping file must be a CSV file."]

        with offline_file.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                return {}, ["ATT&CK mapping CSV is missing a header row."]

            field_map = {field.strip().lower(): field for field in reader.fieldnames if field}
            cve_field = field_map.get("cve_id") or field_map.get("cve")
            if not cve_field:
                return {}, ["ATT&CK mapping CSV must contain a cve_id column."]

            techniques_field = field_map.get("attack_techniques") or field_map.get("techniques")
            tactics_field = field_map.get("attack_tactics") or field_map.get("tactics")
            note_field = field_map.get("attack_note") or field_map.get("note")

            index: dict[str, AttackData] = {}
            requested = set(cve_ids)
            warnings: list[str] = []
            for row_number, row in enumerate(reader, start=2):
                cve_id = normalize_cve_id(row.get(cve_field))
                if row.get(cve_field) and not cve_id:
                    warnings.append(
                        "Ignored ATT&CK mapping row with invalid CVE identifier at "
                        f"line {row_number}: {row.get(cve_field)!r}"
                    )
                    continue
                if not cve_id:
                    continue
                if requested and cve_id not in requested:
                    continue

                techniques = (
                    _split_multi_value(row.get(techniques_field, "")) if techniques_field else []
                )
                tactics = _split_multi_value(row.get(tactics_field, "")) if tactics_field else []
                note = (row.get(note_field) or "").strip() or None if note_field else None

                if cve_id in index:
                    warnings.append(f"ATT&CK mapping overrides duplicate row for {cve_id}.")
                index[cve_id] = AttackData(
                    cve_id=cve_id,
                    mapped=bool(techniques or tactics or note),
                    source="local-csv",
                    attack_techniques=techniques,
                    attack_tactics=tactics,
                    attack_note=note,
                )

        return index, warnings


def _split_multi_value(raw_value: str) -> list[str]:
    normalized_values: list[str] = []
    for part in SEPARATOR_RE.split(raw_value):
        value = part.strip()
        if not value or value in normalized_values:
            continue
        normalized_values.append(value)
    return normalized_values


def _build_metadata(
    *,
    source: str,
    mapping_file: Path | None = None,
    technique_metadata_file: Path | None = None,
    source_version: str | None = None,
    attack_version: str | None = None,
    domain: str | None = None,
    mapping_framework: str | None = None,
    mapping_framework_version: str | None = None,
) -> dict[str, str | None]:
    return {
        "source": source,
        "mapping_file": str(mapping_file) if mapping_file is not None else None,
        "technique_metadata_file": (
            str(technique_metadata_file) if technique_metadata_file is not None else None
        ),
        "source_version": source_version,
        "attack_version": attack_version,
        "domain": domain,
        "mapping_framework": mapping_framework,
        "mapping_framework_version": mapping_framework_version,
    }
