from __future__ import annotations

from datetime import date

import pytest
from pydantic import ValidationError

from app.decision_core.evaluation import ScopeEvaluationInput, evaluate_scope
from app.domain.engine.models import (
    AttackData,
    EpssData,
    InputOccurrence,
    KevData,
    NvdData,
    ProviderEvidence,
    WaiverRule,
)

CVE = "CVE-2026-4242"


def inputs() -> ScopeEvaluationInput:
    return ScopeEvaluationInput(
        cve_id=CVE,
        observations=[
            InputOccurrence(
                cve_id=CVE,
                source_format="generic-occurrence-csv",
                asset_id="web",
                asset_owner="old-owner",
                asset_environment="test",
                asset_exposure="internal",
                asset_criticality="low",
            )
        ],
        provider_evidence=ProviderEvidence(
            nvd=NvdData(cve_id=CVE, cvss_base_score=8.5, cvss_severity="HIGH"),
            epss=EpssData(cve_id=CVE, epss=0.2, percentile=0.8),
            kev=KevData(cve_id=CVE, in_kev=False),
        ),
        attack_data=AttackData(cve_id=CVE),
        evaluation_date=date(2026, 9, 6),
    )


def test_input_roundtrip_replays_all_fields_without_mutating_inputs() -> None:
    original = inputs()
    before = original.model_dump_json()
    restored = ScopeEvaluationInput.model_validate_json(before)
    assert original.fingerprint() == restored.fingerprint()
    assert evaluate_scope(original) == evaluate_scope(restored)
    assert original.model_dump_json() == before


def test_context_update_replaces_score_rationale_and_guidance_together() -> None:
    original = inputs()
    old = evaluate_scope(original)
    new_inputs = original.model_copy(
        update={
            "observations": [
                original.observations[0].model_copy(
                    update={
                        "asset_owner": "new-owner",
                        "asset_environment": "production",
                        "asset_exposure": "internet-facing",
                        "asset_criticality": "critical",
                    }
                )
            ]
        }
    )
    new = evaluate_scope(new_inputs)
    assert new.operational_score > old.operational_score
    assert "new-owner" in new.rationale and "old-owner" not in new.rationale
    assert "production" in new.context_summary and "test" not in new.context_summary
    assert new.decision_guidance != old.decision_guidance
    assert new_inputs.fingerprint() != original.fingerprint()


def test_waiver_expiry_is_replayed_from_explicit_date_once() -> None:
    original = inputs().model_copy(
        update={
            "waiver_rules": [
                WaiverRule(
                    cve_id=CVE,
                    id="exception-1",
                    owner="security",
                    reason="Compensating controls",
                    expires_on="2026-09-10",
                )
            ]
        }
    )
    accepted = evaluate_scope(original)
    expired = evaluate_scope(original.model_copy(update={"evaluation_date": date(2026, 9, 11)}))
    assert accepted.waived is True
    assert accepted.rationale.count("Compensating controls") == 1
    assert expired.waived is False
    assert expired.waiver_status == "expired"
    assert expired.operational_score >= accepted.operational_score


def test_workbench_override_can_be_removed_without_losing_file_waiver() -> None:
    file_rule = WaiverRule(
        cve_id=CVE, id="file", owner="security", reason="File rule", expires_on="2026-10-01"
    )
    api_rule = file_rule.model_copy(update={"id": "api", "reason": "API rule"})
    original = inputs().model_copy(
        update={"waiver_rules": [file_rule], "workbench_waiver": api_rule}
    )
    assert evaluate_scope(original).waiver_id == "api"
    assert (
        evaluate_scope(original.model_copy(update={"workbench_waiver": None})).waiver_id == "file"
    )


def test_input_rejects_mixed_facts_and_unsupported_engine() -> None:
    raw = inputs().model_dump(mode="json")
    raw["provider_evidence"]["epss"]["cve_id"] = "CVE-2026-9999"
    with pytest.raises(ValidationError, match="one CVE"):
        ScopeEvaluationInput.model_validate(raw)
    with pytest.raises(ValueError, match="Unsupported evaluation engine"):
        evaluate_scope(inputs().model_copy(update={"engine_version": "future-engine"}))
