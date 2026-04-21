from __future__ import annotations

import pytest

from vuln_prioritizer.models import (
    AttackData,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityPolicy,
)
from vuln_prioritizer.scoring import determine_cvss_only_priority, determine_priority
from vuln_prioritizer.services.prioritization import PrioritizationService


@pytest.mark.parametrize(
    ("cvss", "epss", "in_kev", "expected"),
    [
        (5.0, 0.05, True, "Critical"),
        (7.2, 0.80, False, "Critical"),
        (9.1, 0.02, False, "High"),
        (6.4, 0.40, False, "High"),
        (7.5, 0.05, False, "Medium"),
        (4.2, 0.10, False, "Medium"),
        (4.2, 0.05, False, "Low"),
    ],
)
def test_determine_priority_matches_mvp_rules(
    cvss: float,
    epss: float,
    in_kev: bool,
    expected: str,
) -> None:
    nvd = NvdData(cve_id="CVE-2024-0001", cvss_base_score=cvss, cvss_severity="HIGH")
    epss_data = EpssData(cve_id="CVE-2024-0001", epss=epss, percentile=0.5)
    kev = KevData(cve_id="CVE-2024-0001", in_kev=in_kev)

    label, _ = determine_priority(nvd, epss_data, kev)

    assert label == expected


@pytest.mark.parametrize(
    ("cvss", "expected_label", "expected_rank"),
    [
        (9.0, "Critical", 1),
        (8.9, "High", 2),
        (7.0, "High", 2),
        (4.0, "Medium", 3),
        (3.9, "Low", 4),
        (None, "Low", 4),
    ],
)
def test_determine_cvss_only_priority_uses_standard_severity_bands(
    cvss: float | None,
    expected_label: str,
    expected_rank: int,
) -> None:
    label, rank = determine_cvss_only_priority(cvss)

    assert label == expected_label
    assert rank == expected_rank


def test_kev_overrides_weaker_signals() -> None:
    nvd = NvdData(cve_id="CVE-2024-0001", cvss_base_score=3.1, cvss_severity="LOW")
    epss_data = EpssData(cve_id="CVE-2024-0001", epss=0.01, percentile=0.01)
    kev = KevData(cve_id="CVE-2024-0001", in_kev=True)

    label, rank = determine_priority(nvd, epss_data, kev)

    assert label == "Critical"
    assert rank == 1


def test_missing_scores_do_not_break_prioritization() -> None:
    nvd = NvdData(cve_id="CVE-2024-0001")
    epss_data = EpssData(cve_id="CVE-2024-0001")
    kev = KevData(cve_id="CVE-2024-0001", in_kev=False)

    label, rank = determine_priority(nvd, epss_data, kev)

    assert label == "Low"
    assert rank == 4


def test_custom_policy_changes_priority_thresholds() -> None:
    policy = PriorityPolicy(high_epss_threshold=0.30)
    nvd = NvdData(cve_id="CVE-2024-0001", cvss_base_score=6.5, cvss_severity="MEDIUM")
    epss_data = EpssData(cve_id="CVE-2024-0001", epss=0.30, percentile=0.7)
    kev = KevData(cve_id="CVE-2024-0001", in_kev=False)

    label, rank = determine_priority(nvd, epss_data, kev, policy)

    assert label == "High"
    assert rank == 2


def test_attack_context_does_not_change_priority() -> None:
    service = PrioritizationService()
    cve_id = "CVE-2024-0001"

    findings_without_attack, _ = service.prioritize(
        [cve_id],
        nvd_data={cve_id: NvdData(cve_id=cve_id, cvss_base_score=9.0, cvss_severity="CRITICAL")},
        epss_data={cve_id: EpssData(cve_id=cve_id, epss=0.2, percentile=0.6)},
        kev_data={cve_id: KevData(cve_id=cve_id, in_kev=False)},
        attack_data={},
    )

    findings_with_attack, _ = service.prioritize(
        [cve_id],
        nvd_data={cve_id: NvdData(cve_id=cve_id, cvss_base_score=9.0, cvss_severity="CRITICAL")},
        epss_data={cve_id: EpssData(cve_id=cve_id, epss=0.2, percentile=0.6)},
        kev_data={cve_id: KevData(cve_id=cve_id, in_kev=False)},
        attack_data={
            cve_id: AttackData(
                cve_id=cve_id,
                attack_techniques=["T1190"],
                attack_tactics=["Initial Access"],
            )
        },
    )

    assert findings_without_attack[0].priority_label == "High"
    assert findings_with_attack[0].priority_label == "High"
    assert findings_with_attack[0].attack_techniques == ["T1190"]


def test_priority_policy_override_descriptions_only_include_changes() -> None:
    policy = PriorityPolicy(high_epss_threshold=0.35, medium_cvss_threshold=6.5)

    assert policy.override_descriptions() == ["high-epss=0.350", "medium-cvss=6.5"]


def test_filter_findings_applies_priority_and_kev_filters() -> None:
    service = PrioritizationService()
    findings = [
        _finding(
            cve_id="CVE-2024-0001",
            priority_label="Critical",
            priority_rank=1,
            cvss=5.0,
            epss=0.05,
            in_kev=True,
        ),
        _finding(
            cve_id="CVE-2024-0002",
            priority_label="High",
            priority_rank=2,
            cvss=9.8,
            epss=0.20,
            in_kev=False,
        ),
    ]

    filtered = service.filter_findings(
        findings,
        priorities={"Critical", "High"},
        kev_only=True,
    )

    assert [finding.cve_id for finding in filtered] == ["CVE-2024-0001"]


def test_filter_findings_excludes_missing_scores_for_thresholds() -> None:
    service = PrioritizationService()
    findings = [
        _finding(
            cve_id="CVE-2024-0001",
            priority_label="Low",
            priority_rank=4,
            cvss=None,
            epss=None,
            in_kev=False,
        ),
        _finding(
            cve_id="CVE-2024-0002",
            priority_label="High",
            priority_rank=2,
            cvss=8.8,
            epss=0.55,
            in_kev=False,
        ),
    ]

    filtered = service.filter_findings(findings, min_cvss=7.0, min_epss=0.10)

    assert [finding.cve_id for finding in filtered] == ["CVE-2024-0002"]


def test_sort_findings_supports_sort_override() -> None:
    service = PrioritizationService()
    findings = [
        _finding(
            cve_id="CVE-2024-0002",
            priority_label="Critical",
            priority_rank=1,
            cvss=7.1,
            epss=0.35,
            in_kev=False,
        ),
        _finding(
            cve_id="CVE-2024-0001",
            priority_label="Medium",
            priority_rank=3,
            cvss=5.5,
            epss=0.90,
            in_kev=False,
        ),
    ]

    by_epss = service.sort_findings(findings, sort_by="epss")
    by_cve = service.sort_findings(findings, sort_by="cve")

    assert [finding.cve_id for finding in by_epss] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert [finding.cve_id for finding in by_cve] == ["CVE-2024-0001", "CVE-2024-0002"]


def test_build_comparison_marks_kev_upgrade() -> None:
    service = PrioritizationService()
    finding = _finding(
        cve_id="CVE-2024-0001",
        priority_label="Critical",
        priority_rank=1,
        cvss=5.0,
        epss=0.05,
        in_kev=True,
    )

    comparison = service.build_comparison([finding])[0]

    assert comparison.cvss_only_label == "Medium"
    assert comparison.enriched_label == "Critical"
    assert comparison.changed is True
    assert comparison.delta_rank == 2
    assert "KEV membership raises" in comparison.change_reason


def test_build_comparison_marks_epss_upgrade() -> None:
    service = PrioritizationService()
    finding = _finding(
        cve_id="CVE-2024-0001",
        priority_label="High",
        priority_rank=2,
        cvss=5.0,
        epss=0.45,
        in_kev=False,
    )

    comparison = service.build_comparison([finding])[0]

    assert comparison.cvss_only_label == "Medium"
    assert comparison.enriched_label == "High"
    assert comparison.changed is True
    assert comparison.delta_rank == 1
    assert "EPSS 0.450 raises" in comparison.change_reason


def test_build_comparison_marks_cvss_only_downgrade() -> None:
    service = PrioritizationService()
    finding = _finding(
        cve_id="CVE-2024-0001",
        priority_label="Medium",
        priority_rank=3,
        cvss=8.0,
        epss=0.05,
        in_kev=False,
    )

    comparison = service.build_comparison([finding])[0]

    assert comparison.cvss_only_label == "High"
    assert comparison.enriched_label == "Medium"
    assert comparison.changed is True
    assert comparison.delta_rank == -1
    assert "lowers it to Medium" in comparison.change_reason


def test_build_comparison_keeps_unchanged_cvss_only_case() -> None:
    service = PrioritizationService()
    finding = _finding(
        cve_id="CVE-2024-0001",
        priority_label="Low",
        priority_rank=4,
        cvss=3.5,
        epss=None,
        in_kev=False,
    )

    comparison = service.build_comparison([finding])[0]

    assert comparison.cvss_only_label == "Low"
    assert comparison.enriched_label == "Low"
    assert comparison.changed is False
    assert comparison.delta_rank == 0
    assert "CVSS alone already yields Low" in comparison.change_reason


def _finding(
    *,
    cve_id: str,
    priority_label: str,
    priority_rank: int,
    cvss: float | None,
    epss: float | None,
    in_kev: bool,
) -> PrioritizedFinding:
    return PrioritizedFinding(
        cve_id=cve_id,
        description="Synthetic finding",
        cvss_base_score=cvss,
        cvss_severity="HIGH" if cvss is not None else None,
        epss=epss,
        epss_percentile=0.8 if epss is not None else None,
        in_kev=in_kev,
        attack_techniques=[],
        priority_label=priority_label,
        priority_rank=priority_rank,
        rationale="Deterministic rationale.",
        recommended_action="Do the deterministic thing.",
    )
