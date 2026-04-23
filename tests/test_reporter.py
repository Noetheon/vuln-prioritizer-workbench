from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.models import AnalysisContext, ComparisonFinding, PrioritizedFinding
from vuln_prioritizer.reporter import (
    generate_compare_markdown,
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
        "Priority | Rationale | Recommended Action | Context Recommendation |"
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
        "Delta | Changed | CVSS | EPSS | KEV | Waiver | Reason |"
    ) in report
    assert "KEV membership raises this CVE" in report
    assert (
        "| CVE-2024-0002 | No change | Low | Low | N.A. | Unmapped | Unmapped | No change | "
        "No | 3.5 | N.A. | No | N.A. |" in report
    )


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
    payload["findings"][0]["attack_note"] = "Representative remote exploitation behavior."
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
    assert "Waiver review due" in html
    assert "owner=security-team" in html
    assert "Representative remote exploitation behavior." in html


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
