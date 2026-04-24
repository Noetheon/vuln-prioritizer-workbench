from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from vuln_prioritizer.db.models import Asset, Finding
from vuln_prioritizer.services.workbench_governance import (
    build_governance_summary,
    compute_owner_rollups,
    summarize_vex,
    summarize_waiver_lifecycle,
)


def test_build_governance_summary_rolls_up_owners_services_waivers_and_vex() -> None:
    findings = [
        _finding(
            cve_id="CVE-2026-0001",
            priority="Critical",
            priority_rank=1,
            risk_score=98.0,
            in_kev=True,
            attack_mapped=True,
            asset=Asset(
                project_id="project-1",
                asset_id="asset-api",
                owner="Platform",
                business_service="Checkout",
            ),
            finding_json={
                "provenance": {
                    "occurrences": [
                        {
                            "asset_owner": "Platform",
                            "asset_business_service": "Checkout",
                            "vex_status": "under_investigation",
                        }
                    ],
                    "vex_statuses": {"under_investigation": 1},
                },
                "under_investigation": True,
            },
        ),
        _finding(
            cve_id="CVE-2026-0002",
            priority="High",
            priority_rank=2,
            status="accepted",
            waived=True,
            asset=Asset(
                project_id="project-1",
                asset_id="asset-worker",
                owner="Payments",
                business_service="Checkout",
            ),
            finding_json={
                "waiver_status": "review_due",
                "waiver_owner": "risk-review",
                "provenance": {
                    "occurrences": [
                        {
                            "asset_owner": "Payments",
                            "asset_business_service": "Checkout",
                        }
                    ]
                },
            },
        ),
        _finding(
            cve_id="CVE-2026-0003",
            priority="Medium",
            priority_rank=3,
            status="suppressed",
            suppressed_by_vex=True,
            finding_json={
                "provenance": {
                    "occurrences": [
                        {
                            "asset_owner": "Platform",
                            "asset_business_service": "Identity",
                            "vex_status": "not_affected",
                        }
                    ],
                    "vex_statuses": {"not_affected": 2},
                },
                "suppressed_by_vex": True,
            },
        ),
        _finding(
            cve_id="CVE-2026-0004",
            priority="Low",
            priority_rank=4,
            finding_json={"waiver_status": "expired", "waiver_owner": "risk-review"},
        ),
    ]

    summary = build_governance_summary(findings)

    assert summary.total_findings == 4

    owners = {rollup.label: rollup for rollup in summary.owner_rollups}
    assert owners["Platform"].finding_count == 2
    assert owners["Platform"].actionable_count == 1
    assert owners["Platform"].suppressed_by_vex_count == 1
    assert owners["Platform"].top_cves == ["CVE-2026-0001", "CVE-2026-0003"]
    assert owners["Payments"].waiver_review_due_count == 1
    assert owners["Unassigned"].expired_waiver_count == 1

    services = {rollup.label: rollup for rollup in summary.service_rollups}
    assert services["Checkout"].finding_count == 2
    assert services["Checkout"].actionable_count == 1
    assert services["Checkout"].critical_count == 1
    assert services["Identity"].suppressed_by_vex_count == 1
    assert services["Unmapped"].expired_waiver_count == 1

    assert summary.waiver_lifecycle.waived_count == 1
    assert summary.waiver_lifecycle.review_due_count == 1
    assert summary.waiver_lifecycle.expired_count == 1
    assert summary.waiver_lifecycle.unwaived_count == 2
    assert summary.waiver_lifecycle.waiver_owner_counts == {"risk-review": 2}

    assert summary.vex.suppressed_findings == 1
    assert summary.vex.under_investigation_findings == 1
    assert summary.vex.status_counts == {"not_affected": 2, "under_investigation": 1}
    assert summary.to_dict()["total_findings"] == 4


def test_rollups_accept_iterables_and_apply_limits() -> None:
    findings = (
        _finding(cve_id=f"CVE-2026-10{index:02d}", priority="High", priority_rank=2)
        for index in range(3)
    )

    rollups = compute_owner_rollups(findings, limit=1, top_cves=2)

    assert len(rollups) == 1
    assert rollups[0].label == "Unassigned"
    assert rollups[0].finding_count == 3
    assert rollups[0].top_cves == ["CVE-2026-1000", "CVE-2026-1001"]


def test_summaries_use_persisted_finding_fields_before_json_fallbacks() -> None:
    suppressed = _finding(
        cve_id="CVE-2026-2001",
        priority="High",
        priority_rank=2,
        suppressed_by_vex=True,
        finding_json={"provenance": {"occurrences": [{"vex_status": "fixed"}]}},
    )
    waived_without_status = _finding(
        cve_id="CVE-2026-2002",
        priority="Medium",
        priority_rank=3,
        waived=True,
        finding_json={},
    )

    waiver_summary = summarize_waiver_lifecycle([suppressed, waived_without_status])
    vex_summary = summarize_vex([suppressed, waived_without_status])

    assert waiver_summary.active_count == 1
    assert waiver_summary.unwaived_count == 1
    assert vex_summary.suppressed_findings == 1
    assert vex_summary.status_counts == {"fixed": 1}


def _finding(
    *,
    cve_id: str,
    priority: str,
    priority_rank: int,
    status: str = "open",
    risk_score: float | None = None,
    in_kev: bool = False,
    attack_mapped: bool = False,
    suppressed_by_vex: bool = False,
    waived: bool = False,
    asset: Asset | None = None,
    finding_json: dict | None = None,
) -> Finding:
    return Finding(
        project_id="project-1",
        vulnerability_id=f"vuln-{cve_id}",
        cve_id=cve_id,
        status=status,
        priority=priority,
        priority_rank=priority_rank,
        risk_score=risk_score,
        in_kev=in_kev,
        attack_mapped=attack_mapped,
        suppressed_by_vex=suppressed_by_vex,
        waived=waived,
        asset=asset,
        finding_json=finding_json or {},
        explanation_json={},
    )
