from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from sqlmodel import Session

from app.core.config import Settings
from app.decision_core.decision_graph import (
    SCOPED_DECISION_STORAGE_VERSION,
    ScopeKey,
    build_scoped_decision_graph,
)
from app.domain.engine.models import (
    AnalysisContext,
    AttackData,
    EpssData,
    InputOccurrence,
    KevData,
    NvdData,
    ParsedInput,
    PrioritizedFinding,
    PriorityPolicy,
    WaiverRule,
)
from app.domain.engine.services.contextualization import aggregate_provenance
from app.domain.engine.services.prioritization import PrioritizationService
from app.services import analysis as workbench_analysis
from app.services.analysis import AnalysisService

CVE_ID = "CVE-2026-4242"


def _context() -> AnalysisContext:
    return AnalysisContext(
        input_path="fixture.csv",
        output_format="json",
        generated_at="2026-09-04T10:00:00Z",
        provider_snapshot_hash="provider-snapshot-sha256",
        attack_mapping_file_sha256="attack-mapping-sha256",
        priority_policy=PriorityPolicy(),
        policy_profile="default",
    )


def _baseline(occurrences: list[InputOccurrence]) -> PrioritizedFinding:
    provenance = aggregate_provenance([CVE_ID], occurrences)
    findings, _ = PrioritizationService().prioritize(
        [CVE_ID],
        nvd_data={
            CVE_ID: NvdData(
                cve_id=CVE_ID,
                description="Deterministic test vulnerability",
                cvss_base_score=8.5,
                cvss_severity="HIGH",
                cvss_version="3.1",
            )
        },
        epss_data={CVE_ID: EpssData(cve_id=CVE_ID, epss=0.2, percentile=0.8)},
        kev_data={CVE_ID: KevData(cve_id=CVE_ID, in_kev=False)},
        attack_data={CVE_ID: AttackData(cve_id=CVE_ID)},
        provenance_by_cve=provenance,
    )
    return findings[0]


def _asset_occurrences() -> list[InputOccurrence]:
    return [
        InputOccurrence(
            cve_id=CVE_ID,
            source_format="scanner-a",
            source_id="scanner-observation-web",
            component_name="openssl",
            component_version="3.0.0",
            purl="pkg:deb/openssl@3.0.0",
            target_ref="image:web",
            asset_id="asset-web",
            asset_exposure="internet-facing",
            asset_environment="production",
            asset_criticality="critical",
        ),
        InputOccurrence(
            cve_id=CVE_ID,
            source_format="scanner-b",
            source_id="scanner-observation-test",
            component_name="openssl",
            component_version="3.0.0",
            purl="pkg:deb/openssl@3.0.0",
            target_ref="image:test",
            asset_id="asset-test",
            asset_exposure="internal",
            asset_environment="test",
            asset_criticality="low",
        ),
    ]


def test_graph_recomputes_scores_per_final_scope_and_ranks_globally() -> None:
    occurrences = _asset_occurrences()
    baseline = _baseline(occurrences)

    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: baseline},
        occurrences=occurrences,
        context=_context(),
    )

    assert graph.schema_version == "scope-first-decision-graph.v2"
    assert graph.fingerprint.schema_version == "scope-first-decision-replay.v2"
    assert len(graph.shared_facts_by_cve) == 1
    assert graph.storage_version == SCOPED_DECISION_STORAGE_VERSION
    assert len(graph.scoped_decisions) == 2
    by_target = {item.scope_key.target_ref: item.decision for item in graph.scoped_decisions}
    assert by_target["image:web"].operational_score > by_target["image:test"].operational_score
    assert by_target["image:web"].explanation is not None
    assert (
        by_target["image:web"].explanation.operational_score
        == by_target["image:web"].operational_score
    )
    assert by_target["image:test"].explanation is not None
    assert (
        by_target["image:test"].explanation.operational_score
        == by_target["image:test"].operational_score
    )
    assert by_target["image:web"].provenance.asset_ids == ["asset-web"]
    assert by_target["image:test"].provenance.asset_ids == ["asset-test"]
    assert sorted(item.operational_rank for item in by_target.values()) == [1, 2]
    assert by_target["image:web"].operational_rank == 1
    assert by_target["image:web"].decision_guidance is not None
    assert by_target["image:test"].decision_guidance is not None
    assert by_target["image:web"].decision_guidance.decision_statement.startswith("Top finding #1:")
    assert by_target["image:test"].decision_guidance.decision_statement.startswith(
        "Top finding #2:"
    )
    assert sum(graph.counts_by_priority.values()) == 2
    assert graph.decision_for_occurrence(occurrences[0]) is not None
    assert (
        graph.scope_index()[ScopeKey.from_occurrence(occurrences[0])].decision
        == by_target["image:web"]
    )


def test_global_scope_ranking_keeps_established_context_tie_breakers() -> None:
    internet = InputOccurrence(
        cve_id=CVE_ID,
        source_format="scanner",
        source_id="internet",
        component_name="demo",
        target_ref="z-internet",
        asset_exposure="internet-facing",
    )
    critical = InputOccurrence(
        cve_id=CVE_ID,
        source_format="scanner",
        source_id="critical-a",
        component_name="demo",
        target_ref="a-critical",
        asset_criticality="critical",
    )
    critical_repeat = critical.model_copy(update={"source_id": "critical-b"})
    occurrences = [critical, internet, critical_repeat]

    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline(occurrences)},
        occurrences=occurrences,
        context=_context(),
    )

    by_target = {item.scope_key.target_ref: item.decision for item in graph.scoped_decisions}
    assert by_target["z-internet"].operational_score == by_target["a-critical"].operational_score
    assert by_target["z-internet"].operational_rank == 1
    assert by_target["a-critical"].operational_rank == 2


def test_scope_identity_ignores_observation_source_but_keeps_provenance() -> None:
    first = InputOccurrence(
        cve_id=CVE_ID,
        source_format="scanner-a",
        source_id="OBS-A",
        component_name="OpenSSL",
        component_version="3.0.0",
        target_ref="asset-1",
    )
    second = first.model_copy(update={"source_format": "scanner-b", "source_id": "OBS-B"})
    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline([first, second])},
        occurrences=[first, second],
        context=_context(),
    )

    assert ScopeKey.from_occurrence(first) == ScopeKey.from_occurrence(second)
    assert len(graph.scoped_decisions) == 1
    scoped = graph.scoped_decisions[0]
    assert scoped.observation_source_ids == ["OBS-A", "OBS-B"]
    assert scoped.decision.provenance.occurrence_count == 2


def test_generic_purl_name_and_version_case_remain_distinct_scopes() -> None:
    upper = InputOccurrence(
        cve_id=CVE_ID,
        component_name="Foo",
        component_version="ReleaseA",
        purl="pkg:generic/Foo@ReleaseA",
        target_ref="shared-target",
    )
    lower = upper.model_copy(
        update={
            "component_name": "foo",
            "component_version": "releasea",
            "purl": "pkg:generic/foo@releasea",
        }
    )

    assert ScopeKey.from_occurrence(upper) != ScopeKey.from_occurrence(lower)
    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline([upper, lower])},
        occurrences=[upper, lower],
        context=_context(),
    )
    assert len(graph.scoped_decisions) == 2


def test_canonical_component_variants_share_one_remediation_bucket() -> None:
    first = InputOccurrence(
        cve_id=CVE_ID,
        component_name="OpenSSL",
        component_version="3.0.0",
        package_type="DEB",
        fix_versions=["3.0.1"],
        target_ref="shared-target",
    )
    second = first.model_copy(
        update={
            "component_name": "  openssl  ",
            "package_type": "deb",
            "fix_versions": ["3.0.2"],
        }
    )

    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline([first, second])},
        occurrences=[first, second],
        context=_context(),
    )

    assert graph.decision_count == 1
    decision = graph.scoped_decisions[0].decision
    assert len(decision.remediation.components) == 1
    component = decision.remediation.components[0]
    assert component.fixed_versions == ["3.0.1", "3.0.2"]
    assert component.occurrence_count == 2


def test_target_kind_is_part_of_scope_and_prevents_vex_leakage() -> None:
    host = InputOccurrence(
        cve_id=CVE_ID,
        source_format="scanner",
        source_id="host-observation",
        component_name="openssl",
        component_version="3.0.0",
        purl="pkg:deb/openssl@3.0.0",
        target_kind="host",
        target_ref="shared-ref",
    )
    image = host.model_copy(
        update={
            "source_id": "image-observation",
            "target_kind": "image",
            "vex_status": "under_investigation",
        }
    )

    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline([host, image])},
        occurrences=[host, image],
        context=_context(),
    )

    assert len(graph.scoped_decisions) == 2
    by_kind = {item.scope_key.target_kind: item.decision for item in graph.scoped_decisions}
    assert by_kind["host"].under_investigation is False
    assert by_kind["host"].provenance.vex_statuses == {}
    assert by_kind["image"].under_investigation is True
    assert by_kind["image"].provenance.vex_statuses == {"under_investigation": 1}


def test_asset_enrichment_does_not_replace_the_stable_source_target_scope() -> None:
    raw = InputOccurrence(
        cve_id=CVE_ID,
        source_format="scanner",
        component_name="openssl",
        purl="pkg:deb/openssl@3.0.0",
        target_kind="host",
        target_ref="prod-app.example",
    )
    enriched = raw.model_copy(update={"asset_id": "asset-prod"})

    assert ScopeKey.from_occurrence(raw) == ScopeKey.from_occurrence(enriched)
    assert ScopeKey.from_occurrence(enriched).target_ref == "prod-app.example"


def test_vex_under_investigation_does_not_leak_between_scopes() -> None:
    occurrences = _asset_occurrences()
    occurrences[0] = occurrences[0].model_copy(update={"vex_status": "under_investigation"})
    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline(occurrences)},
        occurrences=occurrences,
        context=_context(),
    )

    by_target = {item.scope_key.target_ref: item.decision for item in graph.scoped_decisions}
    assert by_target["image:web"].under_investigation is True
    assert by_target["image:web"].provenance.vex_statuses == {"under_investigation": 1}
    assert by_target["image:test"].under_investigation is False
    assert by_target["image:test"].provenance.vex_statuses == {}


def test_terminal_vex_state_and_score_are_scoped() -> None:
    occurrences = _asset_occurrences()
    occurrences[0] = occurrences[0].model_copy(update={"vex_status": "fixed"})
    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline(occurrences)},
        occurrences=occurrences,
        context=_context(),
    )

    by_target = {item.scope_key.target_ref: item.decision for item in graph.scoped_decisions}
    assert by_target["image:web"].suppressed_by_vex is True
    assert by_target["image:web"].priority_state == "Fixed"
    assert by_target["image:web"].operational_score == 0
    assert by_target["image:test"].suppressed_by_vex is False
    assert by_target["image:test"].priority_state == "Medium"
    assert by_target["image:test"].operational_score > 0


def test_waiver_rules_are_reapplied_per_scope_and_fingerprinted() -> None:
    occurrences = _asset_occurrences()
    baseline = _baseline(occurrences)
    waiver = WaiverRule(
        id="accepted-web-risk",
        cve_id=CVE_ID,
        owner="risk-team",
        reason="Temporary compensating controls are in place.",
        expires_on="2027-01-31",
        asset_ids=["asset-web"],
    )

    unwaived_graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: baseline},
        occurrences=occurrences,
        context=_context(),
    )
    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: baseline},
        occurrences=occurrences,
        context=_context(),
        waiver_rules=[waiver],
    )

    by_target = {item.scope_key.target_ref: item.decision for item in graph.scoped_decisions}
    assert by_target["image:web"].waived is True
    assert by_target["image:web"].waiver_status == "active"
    assert by_target["image:web"].waiver_id == "accepted-web-risk"
    assert by_target["image:test"].waived is False
    assert by_target["image:test"].waiver_status is None
    assert graph.waived_count == 1
    assert graph.waiver_review_due_count == 0
    assert graph.expired_waiver_count == 0
    assert graph.fingerprint.policy_sha256 != unwaived_graph.fingerprint.policy_sha256


def test_graph_rejects_unreplayable_cve_level_waiver_state() -> None:
    occurrences = _asset_occurrences()
    waived_baseline = _baseline(occurrences).model_copy(
        update={"waived": True, "waiver_status": "active"}
    )

    with pytest.raises(ValueError, match="requires the original waiver rules"):
        build_scoped_decision_graph(
            findings_by_cve={CVE_ID: waived_baseline},
            occurrences=occurrences,
            context=_context(),
        )


def test_disjoint_scope_waivers_do_not_emit_cve_aggregate_conflict_warning() -> None:
    occurrences = _asset_occurrences()
    rules = [
        WaiverRule(
            id="web-risk",
            cve_id=CVE_ID,
            owner="web-team",
            reason="Web compensating control.",
            expires_on="2027-01-31",
            asset_ids=["asset-web"],
        ),
        WaiverRule(
            id="test-risk",
            cve_id=CVE_ID,
            owner="test-team",
            reason="Test environment acceptance.",
            expires_on="2027-01-31",
            asset_ids=["asset-test"],
        ),
    ]

    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline(occurrences)},
        occurrences=occurrences,
        context=_context(),
        waiver_rules=rules,
    )

    assert graph.waived_count == 2
    assert graph.waiver_warnings == ()
    assert any(
        warning.startswith("Multiple active waivers matched")
        for warning in graph.superseded_waiver_warnings
    )


def test_remediation_is_derived_only_from_the_scoped_component() -> None:
    occurrences = [
        InputOccurrence(
            cve_id=CVE_ID,
            source_format="scanner",
            component_name="xz",
            component_version="5.6.0",
            purl="pkg:apk/xz@5.6.0",
            package_type="apk",
            fix_versions=["5.6.2"],
            asset_id="host-apk",
        ),
        InputOccurrence(
            cve_id=CVE_ID,
            source_format="scanner",
            component_name="liblzma",
            component_version="5.4.1",
            purl="pkg:deb/liblzma@5.4.1",
            package_type="deb",
            asset_id="host-deb",
        ),
    ]
    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: _baseline(occurrences)},
        occurrences=occurrences,
        context=_context(),
    )

    by_target = {item.scope_key.target_ref: item.decision for item in graph.scoped_decisions}
    assert by_target["host-apk"].remediation.strategy == "upgrade"
    assert by_target["host-apk"].remediation.components[0].fixed_versions == ["5.6.2"]
    assert by_target["host-deb"].remediation.strategy == "review-upgrade-options"
    assert by_target["host-deb"].remediation.components[0].name == "liblzma"
    assert "5.6.2" not in by_target["host-deb"].recommended_action
    assert "xz" not in by_target["host-deb"].recommended_action.lower()


def test_replay_fingerprint_and_decisions_are_input_order_independent() -> None:
    occurrences = _asset_occurrences()
    baseline = _baseline(occurrences)
    graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: baseline},
        occurrences=occurrences,
        context=_context(),
    )
    reversed_graph = build_scoped_decision_graph(
        findings_by_cve={CVE_ID: baseline},
        occurrences=list(reversed(occurrences)),
        context=_context().model_copy(
            update={
                "generated_at": "2027-01-01T00:00:00Z",
                "policy_file": "/another-machine/policy.yml",
            }
        ),
    )

    assert graph.fingerprint.replay_sha256 == reversed_graph.fingerprint.replay_sha256
    assert graph.fingerprint.policy_sha256 == reversed_graph.fingerprint.policy_sha256
    assert graph.fingerprint.evaluation_time != reversed_graph.fingerprint.evaluation_time
    assert graph.scoped_decisions == reversed_graph.scoped_decisions


def test_workbench_analysis_result_exposes_additive_scoped_decisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    occurrences = _asset_occurrences()
    baseline = _baseline(occurrences)
    parsed = ParsedInput(
        input_format="generic-occurrence-csv",
        occurrences=occurrences,
        unique_cves=[CVE_ID],
    )
    monkeypatch.setattr(
        workbench_analysis,
        "prepare_analysis",
        lambda request: ([baseline], _context()),
    )
    service = AnalysisService(cast(Session, object()), Settings())

    result = service.analyze_import(
        input_path=Path("fixture.csv"),
        input_type="generic-occurrence-csv",
        parsed_input=parsed,
    )

    assert result.findings_by_cve == {CVE_ID: baseline}
    assert result.decision_graph is not None
    assert len(result.scoped_decisions) == 2
    assert result.scoped_decisions == tuple(result.decision_graph.scoped_decisions)
    assert result.context.findings_count == 2
    assert sum(result.context.counts_by_priority.values()) == 2
