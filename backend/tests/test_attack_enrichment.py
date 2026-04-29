from __future__ import annotations

from vuln_prioritizer.models import AttackData, AttackMapping, AttackTechnique
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService


def test_attack_enrichment_service_marks_high_relevance_for_exploitation_mappings() -> None:
    service = AttackEnrichmentService()

    results = service.enrich_ctid(
        ["CVE-2024-0001", "CVE-2024-0002"],
        mappings_by_cve={
            "CVE-2024-0001": [
                AttackMapping(
                    capability_id="CVE-2024-0001",
                    attack_object_id="T1190",
                    attack_object_name="Exploit Public-Facing Application",
                    mapping_type="exploitation_technique",
                    capability_group="sql_injection",
                )
            ]
        },
        techniques_by_id={
            "T1190": AttackTechnique(
                attack_object_id="T1190",
                name="Exploit Public-Facing Application",
                tactics=["initial-access"],
                url="https://attack.mitre.org/techniques/T1190/",
            )
        },
        source="ctid-mappings-explorer",
        source_version="07/28/2025",
        attack_version="16.1",
        domain="enterprise",
    )

    assert results["CVE-2024-0001"].mapped is True
    assert results["CVE-2024-0001"].attack_relevance == "High"
    assert results["CVE-2024-0001"].attack_techniques == ["T1190"]
    assert results["CVE-2024-0001"].attack_tactics == ["initial-access"]
    assert results["CVE-2024-0002"].mapped is False
    assert results["CVE-2024-0002"].attack_relevance == "Unmapped"


def test_attack_enrichment_summary_counts_mapped_and_unmapped_items() -> None:
    service = AttackEnrichmentService()

    summary = service.summarize(
        [
            AttackData(
                cve_id="CVE-2024-0001",
                mapped=True,
                mapping_types=["exploitation_technique"],
                attack_techniques=["T1190"],
                attack_tactics=["initial-access"],
            ),
            AttackData(
                cve_id="CVE-2024-0002",
                mapped=False,
                attack_relevance="Unmapped",
            ),
        ]
    )

    assert summary.mapped_cves == 1
    assert summary.unmapped_cves == 1
    assert summary.mapping_type_distribution == {"exploitation_technique": 1}
    assert summary.technique_distribution == {"T1190": 1}
    assert summary.tactic_distribution == {"initial-access": 1}


def test_attack_enrichment_surfaces_missing_metadata_in_note_and_rationale() -> None:
    service = AttackEnrichmentService()

    results = service.enrich_ctid(
        ["CVE-2024-0001"],
        mappings_by_cve={
            "CVE-2024-0001": [
                AttackMapping(
                    capability_id="CVE-2024-0001",
                    attack_object_id="T1190",
                    attack_object_name="Exploit Public-Facing Application",
                    mapping_type="primary_impact",
                    comments="Observed impact chain",
                )
            ]
        },
        techniques_by_id={},
        source="ctid-mappings-explorer",
        source_version="07/28/2025",
        attack_version="16.1",
        domain="enterprise",
    )

    attack = results["CVE-2024-0001"]
    assert attack.mapped is True
    assert attack.attack_relevance == "High"
    assert attack.attack_note is not None
    assert "Local ATT&CK technique metadata is unavailable for: T1190." in attack.attack_note
    assert attack.attack_rationale is not None
    assert "Local ATT&CK technique metadata is unavailable for: T1190." in attack.attack_rationale


def test_attack_enrichment_legacy_csv_rationale_marks_mode_as_legacy() -> None:
    service = AttackEnrichmentService()

    results = service.enrich_legacy_csv(
        ["CVE-2024-0001"],
        attack_data={
            "CVE-2024-0001": AttackData(
                cve_id="CVE-2024-0001",
                mapped=True,
                attack_techniques=["T1059"],
                attack_tactics=["Execution"],
                attack_note="Legacy demo note.",
            )
        },
    )

    assert results["CVE-2024-0001"].attack_rationale is not None
    assert "Legacy local ATT&CK CSV context" in results["CVE-2024-0001"].attack_rationale
    assert "Prefer --attack-source ctid-json" in results["CVE-2024-0001"].attack_rationale
