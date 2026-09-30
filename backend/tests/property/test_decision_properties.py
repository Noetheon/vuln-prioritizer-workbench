from __future__ import annotations

from datetime import date, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st
from utils.property_profiles import property_settings

from app.decision_core.evaluation import ScopeEvaluationInput, evaluate_scope_with_diagnostics
from app.domain.engine.models import (
    AttackData,
    DefensiveContext,
    EpssData,
    InputOccurrence,
    KevData,
    NvdData,
    PriorityPolicy,
    ProviderDataQualityFlag,
    ProviderEvidence,
    SeverityProxy,
    WaiverRule,
)
from app.domain.engine.scoring import (
    clamp_operational_score,
    determine_priority,
    effective_cvss,
)

pytestmark = pytest.mark.property
PROPERTY_SETTINGS = property_settings()
CVE = "CVE-2026-4242"
cvss_scores = st.one_of(st.none(), st.integers(0, 100).map(lambda n: n / 10))
epss_scores = st.one_of(st.none(), st.integers(0, 100).map(lambda n: n / 100))


@st.composite
def priority_policies(draw: st.DrawFn) -> PriorityPolicy:
    epss = sorted(draw(st.lists(st.integers(0, 100), min_size=3, max_size=3, unique=True)))
    cvss = sorted(draw(st.lists(st.integers(0, 100), min_size=2, max_size=2, unique=True)))
    return PriorityPolicy(
        medium_epss_threshold=epss[0] / 100,
        high_epss_threshold=epss[1] / 100,
        critical_epss_threshold=epss[2] / 100,
        medium_cvss_threshold=cvss[0] / 10,
        high_cvss_threshold=cvss[1] / 10,
        critical_cvss_threshold=draw(st.integers(0, 100)) / 10,
    )


@PROPERTY_SETTINGS
@given(cvss=cvss_scores, epss=epss_scores, policy=priority_policies())
def test_kev_has_priority_even_with_missing_or_weak_scores(
    cvss: float | None,
    epss: float | None,
    policy: PriorityPolicy,
) -> None:
    assert determine_priority(
        NvdData(cve_id=CVE, cvss_base_score=cvss),
        EpssData(cve_id=CVE, epss=epss),
        KevData(cve_id=CVE, in_kev=True),
        policy,
    ) == ("Critical", 1)


@pytest.mark.parametrize(
    "boundary,expected",
    [("critical", ("Critical", 1)), ("high", ("High", 2)), ("medium", ("Medium", 3))],
)
@PROPERTY_SETTINGS
@given(policy=priority_policies())
def test_generated_policy_thresholds_are_inclusive(
    policy: PriorityPolicy,
    boundary: str,
    expected: tuple[str, int],
) -> None:
    cvss = policy.critical_cvss_threshold if boundary == "critical" else None
    epss = getattr(policy, f"{boundary}_epss_threshold")
    assert (
        determine_priority(
            NvdData(cve_id=CVE, cvss_base_score=cvss),
            EpssData(cve_id=CVE, epss=epss),
            KevData(cve_id=CVE, in_kev=False),
            policy,
        )
        == expected
    )


@PROPERTY_SETTINGS
@given(
    first=st.tuples(st.integers(0, 100), st.integers(0, 100)),
    second=st.tuples(st.integers(0, 100), st.integers(0, 100)),
    policy=priority_policies(),
)
def test_stronger_base_signals_cannot_lower_the_base_priority(
    first: tuple[int, int],
    second: tuple[int, int],
    policy: PriorityPolicy,
) -> None:
    lower = (min(first[0], second[0]) / 10, min(first[1], second[1]) / 100)
    upper = (max(first[0], second[0]) / 10, max(first[1], second[1]) / 100)
    ranks = [
        determine_priority(
            NvdData(cve_id=CVE, cvss_base_score=cvss),
            EpssData(cve_id=CVE, epss=epss),
            KevData(cve_id=CVE, in_kev=False),
            policy,
        )[1]
        for cvss, epss in (lower, upper)
    ]
    assert ranks[1] <= ranks[0]


@PROPERTY_SETTINGS
@given(cvss=cvss_scores, proxy_floor=st.integers(0, 100).map(lambda n: n / 10))
def test_severity_proxy_only_supplies_missing_nvd_cvss(
    cvss: float | None,
    proxy_floor: float,
) -> None:
    nvd = NvdData(cve_id=CVE, cvss_base_score=cvss)
    proxy = SeverityProxy(
        severity="HIGH",
        cvss_floor=proxy_floor,
        raw_value=str(proxy_floor),
        source_format="generic-occurrence-csv",
    )
    expected = (proxy_floor, True) if cvss is None else (cvss, False)
    assert effective_cvss(nvd, proxy) == expected
    assert effective_cvss(nvd) == (cvss, False)


@PROPERTY_SETTINGS
@given(score=st.integers(-10000, 10000))
def test_operational_score_clamps_only_outside_the_documented_range(score: int) -> None:
    assert clamp_operational_score(score) == sorted([0, score, 100])[1]


@PROPERTY_SETTINGS
@given(
    cvss=cvss_scores,
    epss=epss_scores,
    kev=st.booleans(),
    expiry_offset=st.integers(-2, 2),
    exposure=st.sampled_from(["internal", "internet-facing", "unknown"]),
)
def test_scope_replay_preserves_evidence_and_applies_explicit_waiver_date(
    cvss: float | None,
    epss: float | None,
    kev: bool,
    expiry_offset: int,
    exposure: str,
) -> None:
    today = date(2030, 5, 10)
    context = DefensiveContext(cve_id=CVE, source="reviewed-fixture", title="Review evidence")
    flag = ProviderDataQualityFlag(source="nvd", code="fixture-warning", message="Fixture data")
    inputs = ScopeEvaluationInput(
        cve_id=CVE,
        observations=[
            InputOccurrence(
                cve_id=CVE,
                source_format="generic-occurrence-csv",
                asset_id="web-a",
                asset_owner="scope-owner",
                asset_exposure=exposure,
            )
        ],
        provider_evidence=ProviderEvidence(
            nvd=NvdData(cve_id=CVE, cvss_base_score=cvss),
            epss=EpssData(cve_id=CVE, epss=epss),
            kev=KevData(cve_id=CVE, in_kev=kev),
        ),
        attack_data=AttackData(cve_id=CVE),
        evaluation_date=today,
        waiver_rules=[
            WaiverRule(
                id="scope-waiver",
                cve_id=CVE,
                asset_ids=["web-a"],
                owner="risk-owner",
                reason="Documented risk acceptance",
                expires_on=(today + timedelta(days=expiry_offset)).isoformat(),
            )
        ],
        defensive_contexts=[context],
        data_quality_flags=[flag],
        data_quality_confidence="low",
    )
    before = inputs.model_dump_json()
    decision, warnings = evaluate_scope_with_diagnostics(inputs)
    assert decision.cve_id == CVE
    assert decision.waived is (expiry_offset >= 0)
    assert decision.waiver_status == ("review_due" if expiry_offset >= 0 else "expired")
    assert decision.waiver_id == "scope-waiver"
    assert decision.defensive_contexts == [context]
    assert decision.provider_evidence.defensive_contexts == [context]
    assert decision.data_quality_flags == [flag]
    assert decision.data_quality_confidence == "low"
    assert 0 <= decision.operational_score <= 100
    assert decision.operational_rank == 1
    assert warnings
    assert inputs.model_dump_json() == before
    replayed = ScopeEvaluationInput.model_validate_json(before)
    assert replayed.fingerprint() == inputs.fingerprint()
    assert evaluate_scope_with_diagnostics(replayed) == (decision, warnings)


@PROPERTY_SETTINGS
@given(window=st.integers(0, 60), review_offset=st.integers(-1, 1))
def test_waiver_review_and_expiry_windows_are_inclusive(window: int, review_offset: int) -> None:
    from app.domain.engine.services.waivers import waiver_rule_status

    today = date(2030, 5, 10)
    rule = WaiverRule(
        cve_id=CVE,
        owner="risk-owner",
        reason="Time bounded acceptance",
        expires_on=(today + timedelta(days=window + 1)).isoformat(),
        review_on=(today + timedelta(days=review_offset)).isoformat(),
    )
    assert waiver_rule_status(rule, today=today, review_window_days=window) == (
        "review_due" if review_offset <= 0 else "active"
    )
    boundary = rule.model_copy(
        update={
            "review_on": None,
            "expires_on": (today + timedelta(days=window)).isoformat(),
        }
    )
    assert waiver_rule_status(boundary, today=today, review_window_days=window) == "review_due"
