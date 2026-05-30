from __future__ import annotations

import uuid

from app import models as app_models
from app.services.finding_projection import (
    _finding_attack_context_detail_public,
    _finding_occurrence_public,
)


def test_finding_attack_context_uses_persisted_context_rows() -> None:
    finding = _finding()
    context = app_models.FindingAttackContext(
        id=uuid.uuid4(),
        finding_id=finding.id,
        mapped=True,
        source="curated",
        review_status="reviewed",
        rationale="Reviewed defensive mapping.",
        defensive_note="Use only for defensive detection planning.",
        technique_ids_json=["T1190", "T1059"],
        tactic_ids_json=["Initial Access"],
        mappings_json=[
            {
                "technique": {
                    "attack_object_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactics": ["Initial Access"],
                },
                "confidence": 0.35,
                "mapping_type": "detection_context",
                "references": ["https://attack.mitre.org/techniques/T1190/"],
            },
            {"mapping_type": "invalid-without-technique"},
        ],
    )

    context = _finding_attack_context_detail_public(context, finding)

    assert context is not None
    assert context.mapped is True
    assert context.source == "curated"
    assert context.review_status == "reviewed"
    assert context.confidence == "low"
    assert context.low_confidence is True
    assert context.attack_relevance == "Mapped"
    assert context.technique_ids == ["T1190", "T1059"]
    assert context.tactics == ["Initial Access"]
    assert [mapping.technique_id for mapping in context.mappings] == ["T1190"]
    assert context.mappings[0].technique_name == "Exploit Public-Facing Application"
    assert context.mappings[0].defensive_note is not None
    assert [technique.technique_id for technique in context.techniques] == ["T1190", "T1059"]


def test_finding_attack_context_ignores_missing_v2_evidence() -> None:
    finding = _finding()

    assert _finding_attack_context_detail_public(None, finding) is None


def test_finding_occurrence_public_prefers_evidence_and_falls_back_to_model_context() -> None:
    finding = _finding()
    finding.component = app_models.Component(
        id=uuid.uuid4(),
        name="xz-utils",
        version="5.6.0",
        purl="pkg:rpm/xz-utils@5.6.0",
        ecosystem="rpm",
        package_type="rpm",
    )
    finding.asset = app_models.Asset(
        id=uuid.uuid4(),
        project_id=finding.project_id,
        asset_key="asset-prod",
        name="asset-prod",
        target_ref="host-prod-1",
        owner="platform",
        business_service="identity",
        environment=app_models.AssetEnvironment.PRODUCTION,
        exposure=app_models.AssetExposure.INTERNET_FACING,
        criticality=app_models.AssetCriticality.CRITICAL,
    )
    occurrence = app_models.FindingOccurrence(
        id=uuid.uuid4(),
        finding_id=finding.id,
        analysis_run_id=uuid.uuid4(),
        source="scanner",
        raw_reference="raw-row-1",
        fix_version="5.6.2",
        evidence_json={
            "scanner": "trivy",
            "input_type": "trivy-json",
            "source_id": "trivy",
            "source_record_id": "finding-1",
            "component_name": "liblzma",
            "component_version": "5.6.1",
            "purl": "pkg:deb/liblzma@5.6.1",
            "fix_versions": "5.6.3",
            "target_kind": "container",
            "target_ref": "image:demo",
            "asset_ref": "asset-from-evidence",
            "asset_owner": "evidence-owner",
            "business_service": "payments",
            "asset_exposure": "internal",
            "raw_severity": "critical",
            "vex_status": "under_investigation",
            "vex_justification": "inline_mitigations_already_exist",
            "vex_action_statement": "Verify compensating controls.",
            "vex_match_type": "component",
            "vex_source_format": "openvex",
            "vex_source_record_id": "vex-1",
            "vex_source_path": "/tmp/vex.json",
            "vex_candidate_count": "not-an-int",
        },
    )

    row = _finding_occurrence_public(occurrence, finding)

    assert row.scanner == "trivy"
    assert row.source_format == "trivy-json"
    assert row.source_record_id == "finding-1"
    assert row.component_name == "liblzma"
    assert row.component_version == "5.6.1"
    assert row.purl == "pkg:deb/liblzma@5.6.1"
    assert row.fix_versions == ["5.6.3"]
    assert row.target_ref == "image:demo"
    assert row.asset_ref == "asset-from-evidence"
    assert row.asset_owner == "evidence-owner"
    assert row.asset_business_service == "payments"
    assert row.asset_exposure == "internal"
    assert row.raw_severity == "critical"
    assert row.vex_candidate_count == 0

    fallback = _finding_occurrence_public(
        app_models.FindingOccurrence(
            id=uuid.uuid4(),
            finding_id=finding.id,
            analysis_run_id=uuid.uuid4(),
            source="scanner",
            raw_reference="raw-row-2",
            fix_version="5.6.4",
            evidence_json={"vex_candidate_count": True},
        ),
        finding,
    )

    assert fallback.component_name == "xz-utils"
    assert fallback.component_version == "5.6.0"
    assert fallback.purl == "pkg:rpm/xz-utils@5.6.0"
    assert fallback.fix_versions == ["5.6.4"]
    assert fallback.asset_ref == "asset-prod"
    assert fallback.asset_owner == "platform"
    assert fallback.asset_business_service == "identity"
    assert fallback.asset_exposure == "internet-facing"
    assert fallback.vex_candidate_count == 0


def _finding(**overrides: object) -> app_models.Finding:
    values = {
        "id": uuid.uuid4(),
        "project_id": uuid.uuid4(),
        "vulnerability_id": uuid.uuid4(),
        "cve_id": "CVE-2024-3094",
        "status": app_models.FindingStatus.OPEN,
        "priority": app_models.FindingPriority.HIGH,
        "priority_rank": 2,
        "risk_score": 87,
        "operational_rank": 1,
        "recommended_action": "Patch affected systems.",
        "rationale": "Remote code execution risk.",
    }
    values.update(overrides)
    return app_models.Finding(**values)
