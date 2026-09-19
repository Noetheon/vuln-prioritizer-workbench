from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, cast

import pytest
from sqlmodel import Session

from app.core.config import Settings
from app.domain.engine.models import (
    DefensiveContext,
    EnrichmentResult,
    EpssData,
    InputOccurrence,
    KevData,
    NvdData,
    ParsedInput,
    ProviderDataQualityFlag,
)
from app.domain.engine.services.enrichment import EnrichmentService
from app.domain.engine.services.prioritization import PrioritizationService
from app.services.analysis import AnalysisService


def test_workbench_evaluates_each_final_scope_once_and_preserves_provider_facts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Duplicate observations enrich once and never trigger preliminary CVE scoring."""
    cve_id = "CVE-2026-4242"
    missing_cve = "CVE-2026-4243"
    internet = InputOccurrence(
        cve_id=cve_id,
        source_format="scanner",
        source_id="observation-1",
        target_ref="image:web",
        asset_id="asset-web",
        asset_exposure="internet-facing",
        asset_environment="production",
        asset_criticality="critical",
    )
    internal = internet.model_copy(
        update={
            "source_id": "observation-2",
            "target_ref": "image:test",
            "asset_id": "asset-test",
            "asset_exposure": "internal",
            "asset_environment": "test",
            "asset_criticality": "low",
        }
    )
    parsed = ParsedInput(
        input_format="generic-occurrence-csv",
        unique_cves=[cve_id, missing_cve],
        occurrences=[
            internet,
            internet.model_copy(update={"source_id": "duplicate-observation"}),
            internal,
            internal.model_copy(update={"cve_id": missing_cve, "source_id": "missing"}),
        ],
    )
    defensive = DefensiveContext(cve_id=cve_id, source="ssvc", ssvc_decision="Act")
    facts = EnrichmentResult(
        nvd={cve_id: NvdData(cve_id=cve_id, cvss_base_score=8.5)},
        epss={
            cve_id: EpssData(cve_id=cve_id, epss=0.2, percentile=0.8),
            missing_cve: EpssData(cve_id=missing_cve, epss=0.1, percentile=0.7),
        },
        kev={cve_id: KevData(cve_id=cve_id, in_kev=False)},
        defensive_contexts={cve_id: [defensive]},
        defensive_context_sources=["ssvc"],
        provider_data_quality_flags={
            "nvd": [
                ProviderDataQualityFlag(
                    source="nvd", code="provider_error", message="Partial lookup failed."
                ),
                ProviderDataQualityFlag(
                    source="nvd",
                    code="nvd_missing",
                    message="No record.",
                    severity="error",
                    cve_id=missing_cve,
                ),
                ProviderDataQualityFlag(
                    source="nvd", code="provider_missing_data", message="1 missing record."
                ),
            ],
            "snapshot": [
                ProviderDataQualityFlag(
                    source="snapshot", code="snapshot_locked", message="Locked facts."
                )
            ],
        },
    )
    enrichment_calls: list[list[str]] = []
    evaluated_cves: list[str] = []
    original_prioritize = PrioritizationService.prioritize

    def enrich(_self: EnrichmentService, cve_ids: list[str], **_kwargs: Any) -> EnrichmentResult:
        enrichment_calls.append(cve_ids)
        return facts.model_copy(deep=True)

    def prioritize(self: PrioritizationService, cve_ids: list[str], **kwargs: Any) -> Any:
        evaluated_cves.extend(cve_ids)
        return original_prioritize(self, cve_ids, **kwargs)

    monkeypatch.setattr(EnrichmentService, "enrich", enrich)
    monkeypatch.setattr(PrioritizationService, "prioritize", prioritize)
    service = AnalysisService(
        cast(Session, object()),
        Settings(PROVIDER_CACHE_DIR=str(tmp_path / "cache"), DEMO_PROVIDER_SNAPSHOT_ENABLED=False),
    )
    result = service.analyze_import(
        input_path=tmp_path / "fixture.csv",
        input_type="generic-occurrence-csv",
        parsed_input=parsed,
        persist_snapshot=False,
    )

    assert enrichment_calls == [[cve_id, missing_cve]]
    assert Counter(evaluated_cves) == {cve_id: 2, missing_cve: 1}
    assert result.findings_by_cve == {}
    assert result.context.findings_count == 3
    assert result.context.defensive_context_hits == 1
    decisions = {
        (item.decision.cve_id, item.scope_key.target_ref): item.decision
        for item in result.scoped_decisions
    }
    assert (
        decisions[cve_id, "image:web"].operational_score
        > decisions[cve_id, "image:test"].operational_score
    )
    assert sorted(item.operational_rank for item in decisions.values()) == [1, 2, 3]
    for target in ("image:web", "image:test"):
        decision = decisions[cve_id, target]
        assert decision.provider_evidence is not None
        assert decision.provider_evidence.nvd == facts.nvd[cve_id]
        assert decision.provider_evidence.epss == facts.epss[cve_id]
        assert decision.defensive_contexts == [defensive]
        assert decision.provider_evidence.defensive_contexts == [defensive]
        assert [flag.code for flag in decision.data_quality_flags] == ["snapshot_locked"]
        assert decision.data_quality_confidence == "high"
    missing = decisions[missing_cve, "image:test"]
    assert missing.provider_evidence is not None
    assert missing.provider_evidence.nvd == NvdData(cve_id=missing_cve)
    assert missing.defensive_contexts == []
    assert {flag.code for flag in missing.data_quality_flags} == {
        "provider_error",
        "nvd_missing",
        "snapshot_locked",
    }
    assert missing.data_quality_confidence == "low"
