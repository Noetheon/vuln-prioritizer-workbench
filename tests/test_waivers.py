from __future__ import annotations

from datetime import date

from vuln_prioritizer.models import PrioritizedFinding, WaiverRule
from vuln_prioritizer.services.waivers import apply_waivers, summarize_waiver_rules


def _finding(cve_id: str) -> PrioritizedFinding:
    return PrioritizedFinding(
        cve_id=cve_id,
        priority_label="High",
        priority_rank=2,
        rationale="High EPSS with a visible remediation path.",
        recommended_action="Patch immediately.",
    )


def test_summarize_waiver_rules_counts_active_review_due_and_expired() -> None:
    summary = summarize_waiver_rules(
        [
            WaiverRule(
                id="active",
                cve_id="CVE-2024-0001",
                owner="team-a",
                reason="Accepted for now.",
                expires_on="2026-05-30",
            ),
            WaiverRule(
                id="review-due",
                cve_id="CVE-2024-0002",
                owner="team-b",
                reason="Needs review.",
                expires_on="2026-04-28",
            ),
            WaiverRule(
                id="expired",
                cve_id="CVE-2024-0003",
                owner="team-c",
                reason="Expired already.",
                expires_on="2026-04-01",
            ),
        ],
        today=date(2026, 4, 21),
    )

    assert summary.total_rules == 3
    assert summary.active_count == 1
    assert summary.review_due_count == 1
    assert summary.expired_count == 1


def test_apply_waivers_marks_review_due_and_expired_findings() -> None:
    findings, warnings = apply_waivers(
        [_finding("CVE-2024-0001"), _finding("CVE-2024-0002")],
        [
            WaiverRule(
                id="review-due",
                cve_id="CVE-2024-0001",
                owner="risk-review",
                reason="Deferred until the next maintenance window.",
                expires_on="2026-04-25",
                review_on="2026-04-20",
            ),
            WaiverRule(
                id="expired",
                cve_id="CVE-2024-0002",
                owner="risk-review",
                reason="Past the approved window.",
                expires_on="2026-04-01",
            ),
        ],
        today=date(2026, 4, 21),
    )

    by_cve = {finding.cve_id: finding for finding in findings}

    assert by_cve["CVE-2024-0001"].waived is True
    assert by_cve["CVE-2024-0001"].waiver_status == "review_due"
    assert by_cve["CVE-2024-0001"].waiver_days_remaining == 4
    assert by_cve["CVE-2024-0002"].waived is False
    assert by_cve["CVE-2024-0002"].waiver_status == "expired"
    assert by_cve["CVE-2024-0002"].waiver_days_remaining == -20
    assert any("review due" in warning for warning in warnings)
    assert any("expired waiver" in warning for warning in warnings)
