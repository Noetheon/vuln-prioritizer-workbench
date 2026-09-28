from __future__ import annotations

from datetime import date

import pytest

from app.decision_core.evaluation import (
    EVALUATION_ENGINE_VERSION,
    ScopeEvaluationInput,
    evaluate_scope,
)
from app.domain.engine.models import (
    AttackData,
    EpssData,
    InputOccurrence,
    KevData,
    NvdData,
    PriorityLabel,
    ProviderEvidence,
    SeverityProxy,
)
from app.domain.engine.scoring import build_priority_drivers, determine_priority
from app.domain.engine.severity_proxy import (
    normalize_reported_severity,
    severity_proxy_for_occurrences,
)

CVE = "CVE-2026-99001"


@pytest.mark.parametrize(
    ("raw", "source_format", "expected"),
    [
        ("CRITICAL", "trivy-json", "critical"),
        ("Critical", "grype-json", "critical"),
        ("important", "generic-occurrence-csv", "high"),
        ("Moderate", "github-alerts-json", "medium"),
        ("LOW", "dependency-check-json", "low"),
        ("Negligible", "grype-json", None),
        ("UNKNOWN", "trivy-json", None),
        ("None", "nessus-xml", None),
        ("4", "nessus-xml", "critical"),
        ("3", "nessus-xml", "high"),
        ("0", "nessus-xml", None),
        ("9.8", "openvas-xml", "critical"),
        ("7.5", "openvas-xml", "high"),
        ("4", "openvas-xml", "medium"),
        ("0.0", "openvas-xml", None),
        ("11", "openvas-xml", None),
        ("nan", "openvas-xml", None),
        ("", "trivy-json", None),
        (None, "trivy-json", None),
    ],
)
def test_reported_severity_maps_to_cvss_bands(
    raw: str | None,
    source_format: str,
    expected: str | None,
) -> None:
    assert normalize_reported_severity(raw, source_format=source_format) == expected


def test_scope_proxy_uses_the_highest_reported_band() -> None:
    proxy = severity_proxy_for_occurrences(
        [
            InputOccurrence(cve_id=CVE, source_format="grype-json", raw_severity="Medium"),
            InputOccurrence(cve_id=CVE, source_format="trivy-json", raw_severity="CRITICAL"),
            InputOccurrence(cve_id=CVE, source_format="trivy-json", raw_severity=None),
        ]
    )

    assert proxy == SeverityProxy(
        severity="critical",
        cvss_floor=9.0,
        raw_value="CRITICAL",
        source_format="trivy-json",
    )
    assert severity_proxy_for_occurrences([InputOccurrence(cve_id=CVE)]) is None


def test_proxy_only_applies_when_nvd_cvss_is_missing() -> None:
    critical = SeverityProxy(
        severity="critical", cvss_floor=9.0, raw_value="CRITICAL", source_format="trivy-json"
    )
    no_epss = EpssData(cve_id=CVE)
    no_kev = KevData(cve_id=CVE, in_kev=False)

    unknown = determine_priority(NvdData(cve_id=CVE), no_epss, no_kev)
    proxied = determine_priority(NvdData(cve_id=CVE), no_epss, no_kev, severity_proxy=critical)
    escalated = determine_priority(
        NvdData(cve_id=CVE),
        EpssData(cve_id=CVE, epss=0.8),
        no_kev,
        severity_proxy=critical,
    )
    analyzed = determine_priority(
        NvdData(cve_id=CVE, cvss_base_score=5.0),
        no_epss,
        no_kev,
        severity_proxy=critical,
    )

    assert unknown[0] == PriorityLabel.LOW
    assert proxied[0] == PriorityLabel.HIGH
    assert escalated[0] == PriorityLabel.CRITICAL
    assert analyzed[0] == PriorityLabel.LOW
    assert build_priority_drivers(
        NvdData(cve_id=CVE), no_epss, no_kev, severity_proxy=critical
    ) == ["high-severity-proxy", "medium-severity-proxy"]
    assert build_priority_drivers(
        NvdData(cve_id=CVE, cvss_base_score=9.1), no_epss, no_kev, severity_proxy=critical
    ) == ["high-cvss", "medium-cvss"]


def _unanalyzed_inputs(raw_severity: str | None) -> ScopeEvaluationInput:
    return ScopeEvaluationInput(
        cve_id=CVE,
        observations=[
            InputOccurrence(
                cve_id=CVE,
                source_format="trivy-json",
                raw_severity=raw_severity,
                component_name="libfoo",
                component_version="1.0.0",
                target_kind="image",
                target_ref="web-1",
            )
        ],
        provider_evidence=ProviderEvidence(
            nvd=NvdData(cve_id=CVE),
            epss=EpssData(cve_id=CVE),
            kev=KevData(cve_id=CVE, in_kev=False),
        ),
        attack_data=AttackData(cve_id=CVE),
        evaluation_date=date(2026, 9, 28),
    )


def test_unanalyzed_critical_cve_is_not_ranked_as_safe() -> None:
    proxied = evaluate_scope(_unanalyzed_inputs("CRITICAL"))
    unknown = evaluate_scope(_unanalyzed_inputs(None))

    assert proxied.priority_label == "High"
    assert unknown.priority_label == "Low"
    assert proxied.cvss_base_score is None
    assert proxied.severity_proxy is not None
    assert proxied.severity_proxy.severity == "critical"
    assert proxied.operational_score > unknown.operational_score
    assert "high reported severity band (no NVD CVSS): +5" in proxied.operational_score_reasons
    assert "lower bound CVSS 9.0" in proxied.rationale
    assert proxied.explanation is not None
    assert "priority.high.severity_proxy" in proxied.explanation.reason_codes
    assert proxied.decision_guidance is not None
    assert proxied.decision_guidance.sla.label != unknown.decision_guidance.sla.label


def test_recorded_v1_inputs_remain_replayable() -> None:
    legacy = _unanalyzed_inputs("HIGH").model_copy(update={"engine_version": "scope-evaluator.v1"})

    assert EVALUATION_ENGINE_VERSION == "scope-evaluator.v2"
    assert evaluate_scope(legacy).priority_label == "Medium"
    with pytest.raises(ValueError, match="Unsupported evaluation engine"):
        evaluate_scope(legacy.model_copy(update={"engine_version": "scope-evaluator.v0"}))
