from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from app.decision_core.evaluation import (
    EVALUATION_ENGINE_VERSION,
    ScopeEvaluationInput,
    evaluate_scope,
)
from app.domain.engine.inputs.parsers.scanner import parse_grype_json, parse_trivy_json
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
    reported_cvss_score,
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


def test_scope_proxy_prefers_the_most_severe_reported_score() -> None:
    scored = InputOccurrence(
        cve_id=CVE,
        source_format="trivy-json",
        raw_severity="HIGH",
        raw_cvss_score=8.8,
        raw_cvss_source="nvd",
    )
    proxy = severity_proxy_for_occurrences(
        [scored, InputOccurrence(cve_id=CVE, source_format="grype-json", raw_severity="High")]
    )

    assert proxy == SeverityProxy(
        severity="high",
        cvss_floor=8.8,
        raw_value="8.8",
        source_format="trivy-json",
        cvss_source="nvd",
    )
    labelled_critical = InputOccurrence(
        cve_id=CVE, source_format="generic-occurrence-csv", raw_severity="critical"
    )
    assert severity_proxy_for_occurrences([scored, labelled_critical]).cvss_floor == 9.0
    band_only = SeverityProxy(
        severity="high", cvss_floor=7.0, raw_value="HIGH", source_format="trivy-json"
    )
    assert "cvss_source" not in band_only.model_dump()
    assert "raw_cvss_score" not in InputOccurrence(cve_id=CVE).model_dump()
    assert reported_cvss_score("9.81") == 9.8
    for invalid in (True, 0, 10.5, "n/a", float("nan"), None, [7.0]):
        assert reported_cvss_score(invalid) is None


def test_scanner_reports_carry_their_cvss_scores(tmp_path: Path) -> None:
    trivy = tmp_path / "trivy.json"
    trivy.write_text(
        json.dumps(
            {
                "ArtifactName": "app:1",
                "Results": [
                    {
                        "Target": "app:1 (debian 12)",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-0001",
                                "Severity": "HIGH",
                                "SeveritySource": "debian",
                                "CVSS": {
                                    "debian": {"V3Score": 7.5},
                                    "ghsa": {"V3Score": 7.1},
                                    "nvd": {"V2Score": 6.8, "V3Score": 8.1},
                                },
                            },
                            {
                                "VulnerabilityID": "CVE-2026-0002",
                                "Severity": "MEDIUM",
                                "CVSS": {"redhat": {"V40Score": 6.3}},
                            },
                            {
                                "VulnerabilityID": "CVE-2026-0003",
                                "Severity": "LOW",
                                "CVSS": {"nvd": {"V2Score": 5.0}},
                            },
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    grype = tmp_path / "grype.json"
    grype.write_text(
        json.dumps(
            {
                "source": {"type": "image", "target": {"userInput": "app:1"}},
                "matches": [
                    {
                        "vulnerability": {
                            "id": "GHSA-aaaa-bbbb-cccc",
                            "namespace": "github:language:python",
                            "severity": "High",
                            "cvss": [{"version": "3.1", "metrics": {"baseScore": 7.4}}],
                        },
                        "relatedVulnerabilities": [
                            {
                                "id": "CVE-2026-0004",
                                "namespace": "nvd:cpe",
                                "cvss": [
                                    {"version": "2.0", "metrics": {"baseScore": 5.0}},
                                    {"version": "3.1", "metrics": {"baseScore": 8.2}},
                                ],
                            }
                        ],
                        "artifact": {"name": "requests", "version": "2.0.0"},
                    },
                    {
                        "vulnerability": {
                            "id": "CVE-2026-0005",
                            "namespace": "debian:distro:debian:12",
                            "severity": "Medium",
                            "cvss": [{"version": "4.0", "metrics": {"baseScore": 5.3}}],
                        },
                        "artifact": {"name": "libfoo", "version": "1.0"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    trivy_scores = [
        (item.cve_id, item.raw_cvss_score, item.raw_cvss_source)
        for item in parse_trivy_json(trivy).occurrences
    ]
    grype_scores = [
        (item.cve_id, item.raw_cvss_score, item.raw_cvss_source)
        for item in parse_grype_json(grype).occurrences
    ]

    assert trivy_scores == [
        ("CVE-2026-0001", 8.1, "nvd"),
        ("CVE-2026-0002", 6.3, "redhat"),
        ("CVE-2026-0003", None, None),
    ]
    assert grype_scores == [
        ("CVE-2026-0004", 8.2, "nvd"),
        ("CVE-2026-0005", 5.3, "debian"),
    ]


def test_scanner_score_explains_itself_when_nvd_has_not_scored() -> None:
    inputs = _unanalyzed_inputs("HIGH")
    scored = inputs.model_copy(
        update={
            "observations": [
                inputs.observations[0].model_copy(
                    update={"raw_cvss_score": 9.4, "raw_cvss_source": "nvd"}
                )
            ]
        }
    )

    result = evaluate_scope(scored)

    assert result.priority_label == "High"
    assert result.severity_proxy is not None
    assert result.severity_proxy.cvss_source == "nvd"
    assert "reports CVSS 9.4 (critical) from nvd" in result.rationale
