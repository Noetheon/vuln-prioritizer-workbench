from __future__ import annotations

from vuln_prioritizer.models import PrioritizedFinding
from vuln_prioritizer.services.baseline_comparison import (
    build_cvss_baseline_comparison_payload,
)


def test_cvss_baseline_comparison_summarizes_counts_and_top_changes() -> None:
    findings = [
        _finding(
            "CVE-2026-0001",
            cvss=5.5,
            epss=0.91,
            in_kev=True,
            priority_label="Critical",
            priority_rank=1,
        ),
        _finding(
            "CVE-2026-0002",
            cvss=9.8,
            epss=0.02,
            priority_label="High",
            priority_rank=2,
        ),
        _finding(
            "CVE-2026-0003",
            cvss=4.2,
            epss=0.01,
            priority_label="Medium",
            priority_rank=3,
        ),
    ]

    payload = build_cvss_baseline_comparison_payload(
        findings,
        project_id="project-1",
        top_change_limit=2,
    )

    assert payload["project_id"] == "project-1"
    assert payload["counts"]["cvss_only"] == {
        "Critical": 1,
        "High": 0,
        "Medium": 2,
        "Low": 0,
    }
    assert payload["counts"]["enriched"] == {
        "Critical": 1,
        "High": 1,
        "Medium": 1,
        "Low": 0,
    }
    assert payload["summary"] == {
        "total": 3,
        "changed": 2,
        "up": 1,
        "down": 1,
        "unchanged": 1,
    }
    assert len(payload["top_changes"]) == 2
    assert payload["top_changes"][0]["cve_id"] == "CVE-2026-0001"
    assert payload["top_changes"][0]["old_priority"] == "Medium"
    assert payload["top_changes"][0]["old_rank"] == 3
    assert payload["top_changes"][0]["new_priority"] == "Critical"
    assert payload["top_changes"][0]["new_rank"] == 1
    assert payload["top_changes"][0]["direction"] == "up"
    assert "KEV membership raises" in payload["top_changes"][0]["reason"]
    assert "not an absolute truth" in payload["methodology"]["limitations"]
    assert len(payload["comparisons"]) == 3


def test_cvss_baseline_comparison_can_omit_full_rows_for_reports() -> None:
    payload = build_cvss_baseline_comparison_payload(
        [_finding("CVE-2026-0004", cvss=None, priority_label="Low", priority_rank=4)],
        include_comparisons=False,
    )

    assert payload["summary"]["unchanged"] == 1
    assert payload["top_changes"] == []
    assert "comparisons" not in payload


def _finding(
    cve_id: str,
    *,
    cvss: float | None,
    priority_label: str,
    priority_rank: int,
    epss: float | None = None,
    in_kev: bool = False,
) -> PrioritizedFinding:
    return PrioritizedFinding(
        cve_id=cve_id,
        cvss_base_score=cvss,
        epss=epss,
        in_kev=in_kev,
        priority_label=priority_label,
        priority_rank=priority_rank,
        rationale=f"{cve_id} test rationale.",
        recommended_action="Review and remediate according to policy.",
    )
