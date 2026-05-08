from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    AttackMapping,
    AttackTechnique,
    BusinessImpactBlock,
    ComparisonFinding,
    DefensiveContext,
    EpssData,
    ExplanationNote,
    ExplanationReason,
    FindingDecisionGuidance,
    FindingProvenance,
    InputOccurrence,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityExplanation,
    RemediationComponent,
    RemediationPlan,
    SlaTarget,
)
from vuln_prioritizer.reporter import (
    generate_compare_markdown,
    generate_explain_markdown,
    generate_html_report,
    generate_markdown_report,
    write_output,
)


def test_markdown_report_contains_headers_summary_metadata_and_na(tmp_path: Path) -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2024-0001",
        description=None,
        cvss_base_score=None,
        cvss_severity=None,
        epss=None,
        epss_percentile=None,
        in_kev=False,
        attack_techniques=[],
        priority_label="Low",
        priority_rank=4,
        rationale="FIRST EPSS data is unavailable.",
        recommended_action="Document the finding.",
    )
    context = AnalysisContext(
        input_path="data/sample_cves.txt",
        output_path="report.md",
        output_format="markdown",
        generated_at="2026-04-18T00:00:00+00:00",
        attack_enabled=False,
        warnings=[],
        total_input=2,
        valid_input=1,
        findings_count=1,
        filtered_out_count=0,
        nvd_hits=0,
        epss_hits=0,
        kev_hits=0,
        active_filters=["kev-only"],
        counts_by_priority={"Low": 1},
        data_sources=["NVD", "EPSS", "KEV"],
    )

    report = generate_markdown_report([finding], context)

    assert "# Vulnerability Prioritization Report" in report
    assert "## Findings" in report
    assert "- Findings shown: 1" in report
    assert "- Filtered out: 0" in report
    assert "- Waived: 0" in report
    assert "- Active filters: kev-only" in report
    assert "## ATT&CK Context Summary" in report
    assert (
        "| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | "
        "KEV | ATT&CK | Attack Relevance | Sources | Asset Criticality | VEX | Waiver | "
        "Priority | Priority State | Operational Score | Data Quality | Confidence | "
        "Operational Rank | Context Rank Reasons | Rationale | Decision Template | SLA | "
        "Decision Statement | Business Impact | Recommended Action | "
        "Context Recommendation |"
    ) in report
    assert "N.A." in report

    output_file = tmp_path / "report.md"
    write_output(output_file, report)
    assert output_file.read_text(encoding="utf-8") == report


def test_compare_markdown_report_contains_changed_and_unchanged_rows() -> None:
    comparisons = [
        ComparisonFinding(
            cve_id="CVE-2024-0001",
            description="KEV upgrade",
            cvss_base_score=5.0,
            cvss_severity="MEDIUM",
            epss=0.05,
            epss_percentile=0.2,
            in_kev=True,
            cvss_only_label="Medium",
            cvss_only_rank=3,
            enriched_label="Critical",
            enriched_rank=1,
            changed=True,
            delta_rank=2,
            change_reason=(
                "KEV membership raises this CVE from the CVSS-only Medium baseline to Critical."
            ),
        ),
        ComparisonFinding(
            cve_id="CVE-2024-0002",
            description="No change",
            cvss_base_score=3.5,
            cvss_severity="LOW",
            epss=None,
            epss_percentile=None,
            in_kev=False,
            cvss_only_label="Low",
            cvss_only_rank=4,
            enriched_label="Low",
            enriched_rank=4,
            changed=False,
            delta_rank=0,
            change_reason="CVSS alone already yields Low, and EPSS/KEV do not change the result.",
        ),
    ]
    context = AnalysisContext(
        input_path="data/sample_cves.txt",
        output_path="compare.md",
        output_format="markdown",
        generated_at="2026-04-18T00:00:00+00:00",
        attack_enabled=False,
        warnings=[],
        total_input=2,
        valid_input=2,
        findings_count=2,
        filtered_out_count=0,
        nvd_hits=2,
        epss_hits=1,
        kev_hits=1,
        active_filters=[],
        counts_by_priority={"Critical": 1, "Low": 1},
        data_sources=["NVD", "EPSS", "KEV"],
    )

    report = generate_compare_markdown(comparisons, context)

    assert "# Vulnerability Priority Comparison Report" in report
    assert "- Changed rows: 1" in report
    assert "- Unchanged rows: 1" in report
    assert "- Waived: 0" in report
    assert "## ATT&CK Context Summary" in report
    assert (
        "| CVE ID | Description | CVSS-only | Enriched | VEX | ATT&CK | Attack Relevance | "
        "Delta | Changed | CVSS | EPSS | KEV | Data Quality | Confidence | Waiver | Reason |"
    ) in report
    assert "KEV membership raises this CVE" in report
    assert (
        "| CVE-2024-0002 | No change | Low | Low | N.A. | Unmapped | Unmapped | No change | "
        "No | 3.5 | N.A. | No | None | high | N.A. |" in report
    )


def test_markdown_report_renders_attack_defensive_context_and_decision_guidance() -> None:
    finding = _rich_prioritized_finding()
    context = _analysis_context(findings_count=1, attack_enabled=True)

    report = generate_markdown_report([finding], context)

    assert "## CVSS-only Baseline Comparison" in report
    assert "### Top Baseline Changes" in report
    assert "CVE-2024-3094: Medium (rank 3) -> Critical (rank 1)" in report
    assert "## ATT&CK-mapped CVEs" in report
    assert "T1190" in report
    assert "Initial Access" in report
    assert "Reviewed defensive mapping" in report
    assert "| CVE-2024-3094 | OSV, SSVC | OSV-2024-3094, SSVC-2024-3094 |" in report
    assert "component-a 1.2.3" in report
    assert "srv-prod-1" in report
    assert "Emergency patch (24h)" in report
    assert "Patch xz in the production image" in report


def test_explain_markdown_renders_complete_evidence_and_fallback_paths() -> None:
    finding = _rich_prioritized_finding()
    context = _analysis_context(findings_count=1, attack_enabled=True)
    nvd = NvdData(
        cve_id=finding.cve_id,
        description="Backdoored upstream archive allows unauthenticated access.",
        cvss_base_score=5.0,
        cvss_severity="MEDIUM",
        cvss_version="3.1",
        published="2024-03-29T00:00:00Z",
        last_modified="2024-04-01T00:00:00Z",
        cwes=["CWE-506"],
        references=["https://example.test/advisory"],
    )
    epss = EpssData(cve_id=finding.cve_id, epss=0.94, percentile=0.99)
    kev = KevData(
        cve_id=finding.cve_id,
        in_kev=True,
        vendor_project="XZ Utils",
        product="xz",
        date_added="2024-03-29",
        required_action="Apply vendor mitigation.",
        due_date="2024-04-19",
    )
    attack = AttackData(
        cve_id=finding.cve_id,
        mapped=True,
        source="curated",
        attack_relevance="Remote exploitation",
        attack_rationale="Exploitation maps to public-facing application compromise.",
        attack_techniques=["T1190 Exploit Public-Facing Application"],
        attack_tactics=["Initial Access"],
        attack_note="Reviewed defensive mapping.",
        mappings=finding.attack_mappings,
        techniques=finding.attack_technique_details,
    )
    comparison = ComparisonFinding(
        cve_id=finding.cve_id,
        description=finding.description,
        cvss_base_score=5.0,
        cvss_severity="MEDIUM",
        epss=0.94,
        epss_percentile=0.99,
        in_kev=True,
        cvss_only_label="Medium",
        cvss_only_rank=3,
        enriched_label="Critical",
        enriched_rank=1,
        attack_mapped=True,
        attack_relevance="Remote exploitation",
        mapped_technique_count=1,
        changed=True,
        delta_rank=2,
        change_reason="EPSS, KEV, and exposure raise the response.",
        waived=True,
        waiver_owner="risk-review",
        waiver_expires_on="2026-06-01",
    )

    report = generate_explain_markdown(finding, nvd, epss, kev, attack, context, comparison)

    assert "# CVE Explanation: CVE-2024-3094" in report
    assert "- ATT&CK Techniques: T1190 Exploit Public-Facing Application" in report
    assert "| kev | CISA KEV | Known exploited | true | false | KEV overrides baseline |" in report
    assert "- `provider-warning` (NVD, warning): Provider data was partially cached" in report
    assert "| OSV | OSV-2024-3094 | critical | act |" in report
    assert (
        "| component-a 1.2.3 | container:srv-prod-1 | affected | vulnerable_code_present |"
        in report
    )
    assert "| component-a 1.2.3 | /usr/lib/liblzma.so | 5.6.1 | rpm |" in report
    assert "- Required Action: `Apply vendor mitigation.`" in report
    assert "- https://example.test/advisory" in report

    minimal = PrioritizedFinding(
        cve_id="CVE-2024-0002",
        priority_label="Low",
        priority_rank=4,
        rationale="No exploit signals.",
        recommended_action="Track through normal patching.",
    )
    fallback_report = generate_explain_markdown(
        minimal,
        NvdData(cve_id=minimal.cve_id),
        EpssData(cve_id=minimal.cve_id),
        KevData(cve_id=minimal.cve_id),
        AttackData(cve_id=minimal.cve_id),
        _analysis_context(findings_count=1),
    )

    assert "No structured priority explanation was generated." in fallback_report
    assert "| N.A. | No CTID mapping | N.A. | N.A. | N.A. |" in fallback_report
    assert "No OSV, GHSA, Vulnrichment or SSVC context was included." in fallback_report
    assert "| N.A. | N.A. | N.A. | N.A. | N.A. |" in fallback_report
    assert "- N.A." in fallback_report


def _base_html_payload() -> dict:
    return {
        "metadata": {
            "generated_at": "2026-04-21T12:00:00+00:00",
            "input_path": "trivy-results.json",
            "input_format": "trivy-json",
            "policy_profile": "enterprise",
            "cache_enabled": True,
            "merged_input_count": 1,
            "valid_input": 2,
            "findings_count": 1,
            "filtered_out_count": 1,
            "nvd_hits": 2,
            "epss_hits": 2,
            "kev_hits": 1,
            "attack_hits": 0,
            "suppressed_by_vex": 1,
            "under_investigation_count": 1,
            "waived_count": 0,
            "waiver_review_due_count": 0,
            "expired_waiver_count": 0,
            "counts_by_priority": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0},
            "data_sources": ["NVD", "EPSS", "KEV", "Input formats: trivy-json"],
            "warnings": ["Ignored non-CVE identifier GHSA-1234"],
            "attack_enabled": False,
            "duplicate_cve_count": 0,
            "locked_provider_data": False,
            "provider_snapshot_file": "provider-snapshot.json",
            "provider_snapshot_sources": ["nvd", "epss", "kev"],
            "nvd_diagnostics": {
                "requested": 2,
                "cache_hits": 1,
                "network_fetches": 1,
                "failures": 0,
                "content_hits": 2,
            },
            "input_sources": [
                {
                    "input_path": "trivy-results.json",
                    "input_format": "trivy-json",
                    "total_rows": 4,
                    "occurrence_count": 2,
                    "unique_cves": 2,
                }
            ],
        },
        "attack_summary": {
            "mapped_cves": 0,
            "unmapped_cves": 1,
            "technique_distribution": {},
            "tactic_distribution": {},
        },
        "findings": [
            {
                "cve_id": "CVE-2024-3094",
                "description": "Malicious code in xz backdoored upstream release tarballs.",
                "cvss_base_score": 6.8,
                "cvss_severity": "MEDIUM",
                "epss": 0.841,
                "epss_percentile": 0.993,
                "in_kev": False,
                "priority_label": "Critical",
                "priority_rank": 1,
                "rationale": "High EPSS raises this finding above its CVSS-only baseline and keeps it at the top of the queue.",
                "recommended_action": "Upgrade xz immediately and verify downstream image rebuilds.",
                "context_summary": "Seen in 1 occurrence, mapped to an internet-facing production service.",
                "context_recommendation": "Escalate validation and remediation because the affected image backs a production login service.",
                "attack_mapped": False,
                "attack_relevance": "Unmapped",
                "under_investigation": True,
                "waived": False,
                "waiver_status": None,
                "asset_count": 1,
                "highest_asset_criticality": "critical",
                "provenance": {
                    "occurrence_count": 1,
                    "source_formats": ["trivy-json"],
                    "components": ["xz 5.6.0-r0"],
                    "affected_paths": ["/lib/apk/db/installed"],
                    "fix_versions": ["5.6.1-r2"],
                    "targets": ["image:ghcr.io/acme/demo-app:1.0.0"],
                    "asset_ids": ["asset-login-prod"],
                    "highest_asset_criticality": "critical",
                    "highest_asset_exposure": "internet-facing",
                    "vex_statuses": {"under_investigation": 1},
                    "occurrences": [
                        {
                            "cve_id": "CVE-2024-3094",
                            "component_name": "xz",
                            "component_version": "5.6.0-r0",
                            "target_kind": "image",
                            "target_ref": "ghcr.io/acme/demo-app:1.0.0",
                            "asset_id": "asset-login-prod",
                            "asset_business_service": "customer-login",
                            "asset_owner": "platform-team",
                            "asset_exposure": "internet-facing",
                            "asset_environment": "prod",
                            "vex_status": "under_investigation",
                        }
                    ],
                },
                "remediation": {
                    "strategy": "upgrade",
                    "components": [
                        {
                            "name": "xz",
                            "current_version": "5.6.0-r0",
                            "fixed_versions": ["5.6.1-r2"],
                            "package_type": "apk",
                            "path": "/lib/apk/db/installed",
                        }
                    ],
                },
                "provider_evidence": {
                    "nvd": {
                        "cve_id": "CVE-2024-3094",
                        "description": "Malicious code in xz backdoored upstream release tarballs.",
                        "cvss_base_score": 6.8,
                        "cvss_severity": "MEDIUM",
                        "cvss_version": "3.1",
                        "published": "2024-03-29T00:00:00Z",
                        "last_modified": "2024-04-10T00:00:00Z",
                        "cwes": ["CWE-506"],
                        "references": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-100a",
                        ],
                    },
                    "epss": {
                        "cve_id": "CVE-2024-3094",
                        "epss": 0.841,
                        "percentile": 0.993,
                        "date": "2026-04-21",
                    },
                    "kev": {
                        "cve_id": "CVE-2024-3094",
                        "in_kev": False,
                        "vendor_project": "XZ Utils",
                        "product": "xz",
                        "date_added": "2024-04-01",
                        "required_action": "Remove vulnerable versions from production images.",
                        "due_date": "2024-04-05",
                    },
                },
            }
        ],
    }


def _analysis_context(*, findings_count: int, attack_enabled: bool = False) -> AnalysisContext:
    return AnalysisContext(
        input_path="data/sample_cves.txt",
        output_path="report.md",
        output_format="markdown",
        generated_at="2026-04-18T00:00:00+00:00",
        attack_enabled=attack_enabled,
        warnings=["Provider data was partially cached"],
        total_input=findings_count,
        valid_input=findings_count,
        findings_count=findings_count,
        filtered_out_count=0,
        nvd_hits=findings_count,
        epss_hits=findings_count,
        kev_hits=findings_count,
        counts_by_priority={"Critical": findings_count},
        data_sources=["NVD", "EPSS", "KEV", "OSV", "SSVC"],
    )


def _rich_prioritized_finding() -> PrioritizedFinding:
    mapping = AttackMapping(
        capability_id="capability.initial-access",
        attack_object_id="T1190",
        attack_object_name="Exploit Public-Facing Application",
        mapping_type="exploitation",
        capability_group="Initial Access",
        comments="Remote code execution in exposed service",
    )
    technique = AttackTechnique(
        attack_object_id="T1190",
        name="Exploit Public-Facing Application",
        tactics=["Initial Access"],
    )
    occurrence = InputOccurrence(
        cve_id="CVE-2024-3094",
        source_format="cyclonedx",
        component_name="component-a",
        component_version="1.2.3",
        purl="pkg:rpm/component-a@1.2.3",
        package_type="rpm",
        file_path="/usr/lib/liblzma.so",
        fix_versions=["5.6.1"],
        target_kind="container",
        target_ref="srv-prod-1",
        asset_id="asset-prod",
        asset_criticality="critical",
        asset_exposure="internet-facing",
        asset_environment="production",
        asset_owner="platform",
        asset_business_service="identity",
        vex_status="affected",
        vex_justification="vulnerable_code_present",
        vex_action_statement="Patch the affected image.",
    )
    return PrioritizedFinding(
        cve_id="CVE-2024-3094",
        description="xz backdoor in production image",
        cvss_base_score=5.0,
        cvss_severity="MEDIUM",
        cvss_version="3.1",
        epss=0.94,
        epss_percentile=0.99,
        in_kev=True,
        attack_mapped=True,
        attack_relevance="Remote exploitation",
        attack_techniques=["T1190 Exploit Public-Facing Application"],
        attack_tactics=["Initial Access"],
        attack_note="Reviewed defensive mapping.",
        attack_mappings=[mapping],
        attack_technique_details=[technique],
        provenance=FindingProvenance(
            occurrence_count=1,
            active_occurrence_count=1,
            source_formats=["cyclonedx"],
            components=["component-a 1.2.3"],
            affected_paths=["/usr/lib/liblzma.so"],
            fix_versions=["5.6.1"],
            targets=["srv-prod-1"],
            asset_ids=["asset-prod"],
            highest_asset_criticality="critical",
            highest_asset_exposure="internet-facing",
            asset_environments=["production"],
            asset_owners=["platform"],
            asset_business_services=["identity"],
            asset_count=1,
            vex_statuses={"affected": 1},
            occurrences=[occurrence],
        ),
        context_summary="Seen on internet-facing production identity service.",
        context_recommendation="Coordinate emergency patch with platform owner.",
        highest_asset_criticality="critical",
        asset_count=1,
        waived=True,
        waiver_status="approved",
        waiver_owner="risk-review",
        waiver_expires_on="2026-06-01",
        operational_rank=1,
        context_rank_reasons=["KEV", "internet-facing", "production"],
        priority_label="Critical",
        priority_rank=1,
        priority_state="active",
        operational_score=98,
        explanation=PriorityExplanation(
            cve_id="CVE-2024-3094",
            priority_label="Critical",
            priority_state="active",
            operational_score=98,
            summary="Critical because KEV and exposure are both present.",
            human_readable="KEV, EPSS, and production exposure require emergency response.",
            reasons=[
                ExplanationReason(
                    code="kev",
                    source="CISA KEV",
                    signal="Known exploited",
                    value="true",
                    threshold="false",
                    message="KEV overrides baseline",
                )
            ],
            notes=[
                ExplanationNote(
                    code="provider-warning",
                    source="NVD",
                    severity="warning",
                    message="Provider data was partially cached.",
                )
            ],
            recommended_action="Patch xz in the production image.",
        ),
        rationale="KEV, high EPSS, and internet exposure create immediate operational risk.",
        defensive_contexts=[
            DefensiveContext(
                cve_id="CVE-2024-3094",
                source="osv",
                source_id="OSV-2024-3094",
                severity="critical",
                ssvc_decision="act",
                summary="Malicious release affects downstream packages.",
            ),
            DefensiveContext(
                cve_id="CVE-2024-3094",
                source="ssvc",
                source_id="SSVC-2024-3094",
                severity="high",
                ssvc_decision="act",
                title="Prioritize remediation",
            ),
        ],
        remediation=RemediationPlan(
            strategy="upgrade",
            ecosystem="rpm",
            components=[
                RemediationComponent(
                    name="component-a",
                    current_version="1.2.3",
                    fixed_versions=["5.6.1"],
                    package_type="rpm",
                    purl="pkg:rpm/component-a@1.2.3",
                    path="/usr/lib/liblzma.so",
                )
            ],
        ),
        decision_guidance=FindingDecisionGuidance(
            template="patch",
            template_label="Emergency patch",
            sla=SlaTarget(
                priority="Critical",
                label="Emergency patch",
                target_hours=24,
                guidance="Patch within one day.",
            ),
            business_impact=BusinessImpactBlock(
                level="critical",
                text="Potential compromise of internet-facing identity service.",
                drivers=["internet-facing", "production"],
            ),
            decision_statement="Treat as emergency remediation.",
            visibility="Escalate to platform and security leadership.",
        ),
        recommended_action="Patch xz in the production image.",
    )


def test_generate_html_report_contains_bridge_view_sections_and_context() -> None:
    payload = _base_html_payload()

    html = generate_html_report(payload)

    assert 'data-section="executive-brief"' in html
    assert 'data-section="key-signals"' in html
    assert "How to Read This Report" in html
    assert "Coverage &amp; Context" in html
    assert "Decision &amp; Action" in html
    assert "ATT&amp;CK &amp; Governance" in html
    assert "Priority Queue" in html
    assert "Finding Dossiers" in html
    assert "Provider transparency" in html
    assert "Findings by Severity and Signal" in html
    assert "Provider Signals" in html
    assert "Top ATT&amp;CK-Mapped Findings" in html
    assert "Next 30 Days" in html
    assert "Evidence Bundle Contents" in html
    assert "Mapping Confidence" in html
    assert "Action plan" in html
    assert "CVSS-only baseline delta" in html
    assert "Provider evidence" in html
    assert "customer-login" in html
    assert "platform-team" in html
    assert "Under investigation" in html
    assert "Published:" in html
    assert "Score date:" in html
    assert "Due date:" in html
    assert "Raised by 2" in html
    assert "vuln-prioritizer analyze --attack-source ctid-json" in html
    assert "vuln-prioritizer analyze --waiver-file waivers.yml" in html


def test_generate_html_report_renders_attack_and_waiver_states() -> None:
    payload = _base_html_payload()
    payload["metadata"]["attack_enabled"] = True
    payload["metadata"]["attack_hits"] = 1
    payload["metadata"]["waived_count"] = 1
    payload["metadata"]["waiver_review_due_count"] = 1
    payload["metadata"]["waiver_file"] = "waivers.yml"
    payload["attack_summary"] = {
        "mapped_cves": 1,
        "unmapped_cves": 0,
        "technique_distribution": {"T1190": 1},
        "tactic_distribution": {"initial-access": 1},
    }
    payload["findings"][0]["attack_mapped"] = True
    payload["findings"][0]["attack_relevance"] = "High"
    payload["findings"][0]["attack_tactics"] = ["initial-access"]
    payload["findings"][0]["attack_techniques"] = ["T1190"]
    payload["findings"][0]["attack_note"] = "Representative source-backed defensive behavior."
    payload["findings"][0]["attack_mappings"] = [{"mapping_type": "exploitation_technique"}]
    payload["findings"][0]["waived"] = True
    payload["findings"][0]["waiver_status"] = "review_due"
    payload["findings"][0]["waiver_owner"] = "security-team"
    payload["findings"][0]["waiver_expires_on"] = "2026-05-01"
    payload["findings"][0]["waiver_review_on"] = "2026-04-25"

    html = generate_html_report(payload)

    assert "Mapped CVEs" in html
    assert "T1190 (1)" in html
    assert "initial-access (1)" in html
    assert "ATT&amp;CK High" in html
    assert "Defensive review sequence only. Not a confirmed attack path" in html
    assert "it is not exploit proof" in html
    assert "Waiver review due" in html
    assert "owner=security-team" in html
    assert "Representative source-backed defensive behavior." in html


def test_generate_html_report_handles_empty_findings_state() -> None:
    payload = _base_html_payload()
    payload["metadata"]["findings_count"] = 0
    payload["metadata"]["filtered_out_count"] = 2
    payload["metadata"]["suppressed_by_vex"] = 1
    payload["findings"] = []

    html = generate_html_report(payload)

    assert "No visible findings matched this export." in html
    assert "0 visible finding(s)" in html
    assert "Suppressed by VEX" in html


def test_generate_html_report_escapes_dynamic_content() -> None:
    payload = {
        "metadata": {
            "generated_at": '2026-04-21T00:00:00+00:00<script>alert("x")</script>',
            "input_path": 'input.json"><script>alert("x")</script>',
            "input_format": "json",
            "policy_profile": "<b>enterprise</b>",
            "findings_count": 1,
            "suppressed_by_vex": 0,
            "warnings": [],
            "data_sources": [],
            "input_sources": [],
            "counts_by_priority": {},
        },
        "attack_summary": {"mapped_cves": 1},
        "findings": [
            {
                "cve_id": 'CVE-2024-0001<script>alert("x")</script>',
                "priority_label": "<Critical>",
                "cvss_base_score": 9.8,
                "epss": 0.9,
                "in_kev": True,
                "context_recommendation": '<img src=x onerror="alert(1)">',
                "rationale": 'alert("x")',
                "recommended_action": "Patch now",
                "provenance": {"source_formats": ["scanner<script>"], "occurrences": []},
                "remediation": {"components": []},
            }
        ],
    }

    html = generate_html_report(payload)

    assert "<script>alert(" not in html
    assert "<img src=x onerror" not in html
    assert "&lt;Critical&gt;" in html
    assert "scanner&lt;script&gt;" in html
    assert 'data-section="executive-brief"' in html


def test_write_output_trims_trailing_whitespace(tmp_path: Path) -> None:
    output_file = tmp_path / "report.html"

    write_output(output_file, "alpha  \n beta\t\n")

    assert output_file.read_text(encoding="utf-8") == "alpha\n beta\n"
