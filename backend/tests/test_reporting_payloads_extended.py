from __future__ import annotations

import json

import pytest

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackSummary,
    BusinessImpactBlock,
    DefensiveContext,
    EpssData,
    ExplanationNote,
    ExplanationReason,
    FindingDecisionGuidance,
    FindingProvenance,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityExplanation,
    ProviderDataQualityFlag,
    ProviderEvidence,
    RemediationComponent,
    RemediationPlan,
    SlaTarget,
)
from vuln_prioritizer.reporting_payloads import (
    build_analysis_report_payload,
    generate_sarif_report,
    generate_summary_markdown,
)


def test_summary_markdown_renders_governance_detection_and_baseline_sections() -> None:
    payload = {
        "metadata": {
            "input_path": "merged.json",
            "input_format": "merged",
            "merged_input_count": 2,
            "duplicate_cve_count": 1,
            "asset_match_conflict_count": 2,
            "vex_conflict_count": 3,
            "policy_profile": "enterprise",
            "findings_count": 1,
            "counts_by_priority": {"Critical": 1, "High": 0},
            "kev_hits": 1,
            "suppressed_by_vex": 1,
            "under_investigation_count": 1,
            "waived_count": 1,
            "waiver_review_due_count": 1,
            "expired_waiver_count": 1,
            "input_sources": [
                {
                    "input_path": "trivy.json",
                    "input_format": "trivy-json",
                    "total_rows": 4,
                    "occurrence_count": 2,
                    "unique_cves": 1,
                }
            ],
        },
        "attack_summary": {
            "mapped_cves": 1,
            "technique_distribution": {"T1190": 2, "T1059": 1},
        },
        "detection_coverage": {
            "summary": {"covered": 1, "partial": 1, "not_covered": 1, "unknown": 1},
            "items": [
                {
                    "technique_id": "T1190",
                    "coverage_level": "partial",
                    "recommended_action": "Add edge detection for suspicious requests.",
                },
                {
                    "technique_id": "T1059",
                    "coverage_level": "covered",
                    "recommended_action": "Keep existing controls.",
                },
            ],
        },
        "baseline_comparison": {
            "summary": {"changed": 1, "up": 1, "down": 0, "unchanged": 0},
            "methodology": {"limitations": "Decision support only."},
            "top_changes": [
                {
                    "cve_id": "CVE-2024-3094",
                    "old_priority": "Medium",
                    "old_rank": 3,
                    "new_priority": "Critical",
                    "new_rank": 1,
                    "reason": "KEV and asset exposure raise the result.",
                },
                "ignored",
            ],
        },
        "findings": [
            {
                "cve_id": "CVE-2024-3094",
                "priority_label": "Critical",
                "in_kev": True,
                "waived": True,
                "waiver_status": "accepted",
                "attack_mapped": True,
                "attack_relevance": "High",
                "rationale": "KEV and exposed production service.",
                "recommended_action": "Patch immediately.",
                "decision_guidance": {
                    "decision_statement": "Emergency patch approved.",
                    "sla": {"label": "Emergency", "target_hours": 24},
                },
                "provenance": {
                    "occurrences": [
                        {
                            "asset_owner": "platform",
                            "asset_business_service": "identity",
                        },
                        {
                            "asset_owner": "platform",
                            "asset_business_service": "payments",
                        },
                    ]
                },
            },
            "ignored",
        ],
    }

    markdown = generate_summary_markdown(payload)

    assert "## Input Sources" in markdown
    assert "## Threat-Informed Context" in markdown
    assert "- T1190: 2 mapped finding(s)" in markdown
    assert "## Governance" in markdown
    assert "- Top owners: platform (2)" in markdown
    assert "- Top services: identity (1), payments (1)" in markdown
    assert "## Detection Coverage" in markdown
    assert "### Coverage Gaps" in markdown
    assert "T1190 (partial): Add edge detection" in markdown
    assert "## CVSS-only Baseline Comparison" in markdown
    assert "### Top Baseline Changes" in markdown
    assert "CVE-2024-3094: Medium (rank 3) -> Critical (rank 1)" in markdown
    assert "Emergency patch approved. SLA: Emergency (24h)" in markdown

    compact = generate_summary_markdown(payload, template="compact")
    assert "| Findings shown | Critical | High | KEV hits | ATT&CK mapped" in compact
    assert "CVE-2024-3094 (Critical / KEV / Waived)" in compact
    with pytest.raises(ValueError, match="Unsupported summary template"):
        generate_summary_markdown(payload, template="unknown")


def test_sarif_report_includes_defensive_context_decision_and_component_properties() -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2024-3094",
        description="Backdoored release.",
        cvss_base_score=5.0,
        epss=0.94,
        in_kev=True,
        attack_relevance="High",
        priority_label="Critical",
        priority_rank=1,
        priority_state="Open",
        operational_score=98,
        operational_score_reasons=["kev", "internet-facing"],
        explanation=PriorityExplanation(
            cve_id="CVE-2024-3094",
            priority_label="Critical",
            summary="High-risk finding.",
            human_readable="KEV and exposure require emergency response.",
            reasons=[
                ExplanationReason(
                    code="kev",
                    source="CISA KEV",
                    signal="known exploited",
                    value="true",
                    threshold="false",
                    message="Known exploited vulnerability.",
                )
            ],
            notes=[
                ExplanationNote(
                    code="stale-cache",
                    source="NVD",
                    severity="warning",
                    message="Provider cache is stale.",
                )
            ],
            recommended_action="Patch.",
        ),
        data_quality_flags=[
            ProviderDataQualityFlag(
                source="nvd",
                code="stale-cache",
                message="Provider cache is stale.",
            )
        ],
        provider_evidence=ProviderEvidence(
            nvd=NvdData(
                cve_id="CVE-2024-3094",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                    "https://example.test/advisory",
                ],
            ),
            epss=EpssData(cve_id="CVE-2024-3094", epss=0.94),
            kev=KevData(cve_id="CVE-2024-3094", in_kev=True),
        ),
        defensive_contexts=[
            DefensiveContext(
                cve_id="CVE-2024-3094",
                source="osv",
                source_id="OSV-2024-3094",
                url="https://osv.dev/vulnerability/OSV-2024-3094",
                references=["https://example.test/advisory"],
            )
        ],
        provenance=FindingProvenance(
            source_formats=["trivy-json"],
            components=["xz 5.6.0"],
            affected_paths=["/usr/lib/liblzma.so"],
            targets=["image:demo"],
            asset_ids=["asset-prod"],
        ),
        remediation=RemediationPlan(
            strategy="upgrade",
            ecosystem="rpm",
            components=[
                RemediationComponent(
                    name="xz",
                    current_version="5.6.0",
                    purl="pkg:rpm/xz@5.6.0",
                )
            ],
        ),
        decision_guidance=FindingDecisionGuidance(
            template="patch",
            template_label="Patch",
            sla=SlaTarget(
                priority="Critical",
                label="Emergency",
                target_hours=24,
                guidance="Patch within 24 hours.",
            ),
            business_impact=BusinessImpactBlock(
                level="critical",
                text="Production impact.",
            ),
            decision_statement="Patch production image.",
            visibility="Escalate to owners.",
        ),
        rationale="KEV and exposed production service.",
        recommended_action="Patch immediately.",
    )
    context = AnalysisContext(
        input_path="trivy.json",
        output_format="sarif",
        generated_at="2026-05-08T00:00:00Z",
        schema_version="1.0.0",
        attack_summary=AttackSummary(mapped_cves=1),
    )

    payload = json.loads(generate_sarif_report([finding], context))

    run = payload["runs"][0]
    result = run["results"][0]
    rule = run["tool"]["driver"]["rules"][0]
    properties = result["properties"]
    assert result["level"] == "error"
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "/usr/lib/liblzma.so"
    )
    assert properties["cve"] == "CVE-2024-3094"
    assert properties["explanation_reason_codes"] == ["kev"]
    assert properties["explanation_notes"][0]["code"] == "stale-cache"
    assert properties["data_quality_flag_codes"] == ["stale-cache"]
    assert properties["defensive_context_sources"] == ["osv"]
    assert properties["defensive_context_ids"] == ["OSV-2024-3094"]
    assert properties["remediation_strategy"] == "upgrade"
    assert properties["decision_template"] == "patch"
    assert properties["decision_sla"]["target_hours"] == 24
    assert properties["business_impact"]["text"] == "Production impact."
    assert properties["references"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        "https://example.test/advisory",
        "https://osv.dev/vulnerability/OSV-2024-3094",
    ]
    assert rule["properties"]["security-severity"] == "5.0"
    assert set(result["partialFingerprints"]) == {"vuln-prioritizer/v1"}
    assert len(result["partialFingerprints"]["vuln-prioritizer/v1"]) == 64


def test_analysis_report_payload_omits_empty_provider_quality_flags() -> None:
    context = AnalysisContext(
        input_path="input.txt",
        output_format="json",
        generated_at="2026-05-08T00:00:00Z",
    )

    payload = build_analysis_report_payload([], context)

    assert "provider_data_quality_flags" not in payload["metadata"]
