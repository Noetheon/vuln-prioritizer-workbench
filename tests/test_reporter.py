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


def test_generate_html_report_escapes_dynamic_content() -> None:
    payload = {
        "metadata": {
            "generated_at": '2026-04-21T00:00:00+00:00<script>alert("x")</script>',
            "input_path": 'input.json"><script>alert("x")</script>',
            "input_format": "json",
            "policy_profile": "<b>enterprise</b>",
            "findings_count": 1,
            "suppressed_by_vex": 0,
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
                "provenance": {"source_formats": ["scanner<script>"]},
            }
        ],
    }

    html = generate_html_report(payload)

    assert "<script>alert(" not in html
    assert "<img src=x onerror" not in html
    assert "&lt;Critical&gt;" in html
    assert "scanner&lt;script&gt;" in html


def test_write_output_trims_trailing_whitespace(tmp_path: Path) -> None:
    output_file = tmp_path / "report.html"

    write_output(output_file, "alpha  \n beta\t\n")

    assert output_file.read_text(encoding="utf-8") == "alpha\n beta\n"
