from __future__ import annotations

import hashlib
import uuid
from typing import Any

from app.decision_core.contracts import (
    AnalysisEvidenceUploadsV2,
    AnalysisEvidenceV2,
    AnalysisSemanticsV2,
    AnalysisServiceEvidenceV2,
    AttackEvidenceV2,
    EvidenceUploadRef,
    FindingDecisionEvidenceV2,
    GovernanceEvidenceV2,
    PriorityEvidenceV2,
    ProviderEvidenceV2,
    RemediationEvidenceV2,
    RunCountsV2,
)

_SEED_UPLOAD_CONTENT = b"vpw050-input"
_SEED_UPLOAD_SHA256 = hashlib.sha256(_SEED_UPLOAD_CONTENT).hexdigest()


def _seed_analysis_evidence(
    *,
    project_id: uuid.UUID,
    run: Any,
    provider_snapshot_id: uuid.UUID | None,
    provider_snapshot_hash: str | None,
    finding_count: int,
    counts_by_priority: dict[str, int],
    locked_provider_data: bool,
    findings: list[FindingDecisionEvidenceV2],
) -> AnalysisEvidenceV2:
    return AnalysisEvidenceV2(
        analysis_run_id=str(run.id),
        project_id=str(project_id),
        input_type=run.input_type,
        filename=run.filename,
        status=str(run.status),
        input_sha256=_SEED_UPLOAD_SHA256,
        counts=RunCountsV2(
            finding_count=finding_count,
            occurrence_count=finding_count,
            counts_by_priority=counts_by_priority,
            kev_hits=sum(1 for finding in findings if finding.in_kev),
        ),
        uploads=AnalysisEvidenceUploadsV2(
            input=EvidenceUploadRef(
                input_type=run.input_type,
                original_filename=run.filename,
                stored_filename=run.filename,
                sha256=_SEED_UPLOAD_SHA256,
                size_bytes=len(_SEED_UPLOAD_CONTENT),
                storage_ref=f"{project_id}/{run.id}/{run.filename}",
            )
        ),
        provider=ProviderEvidenceV2(
            provider_snapshot_id=str(provider_snapshot_id) if provider_snapshot_id else None,
            provider_snapshot_hash=provider_snapshot_hash,
            provider_snapshot_file="demo_provider_snapshot.json",
            locked_provider_data=locked_provider_data,
            kev_hits=sum(1 for finding in findings if finding.in_kev),
            epss_hits=sum(1 for finding in findings if finding.epss is not None),
            nvd_hits=sum(1 for finding in findings if finding.cvss_base_score is not None),
        ),
        analysis_service=AnalysisServiceEvidenceV2(
            pipeline="seeded-contract-fixture",
            engine="backend.tests.utils.workbench_evidence_seed",
            kernel="app.decision_core.producer",
        ),
        analysis_semantics=AnalysisSemanticsV2(
            analysis_decision_scope="seeded_decision_scope",
            persistence_scope="seeded_finding_scope",
            finding_dedup_key_version="seed-v1",
            cve_count=finding_count,
            occurrence_count=finding_count,
            finding_count=finding_count,
        ),
    )


def _seed_finding_evidence(
    *,
    finding: Any,
    analysis_run_id: uuid.UUID,
    project_id: uuid.UUID,
    asset_key: str,
    asset_name: str,
    component_name: str,
    component_version: str,
    component_purl: str | None = None,
    component_package_type: str | None = None,
    priority: Any,
    priority_rank: int,
    risk_score: float,
    operational_rank: int,
    epss: float,
    cvss: float,
    in_kev: bool,
    rationale: str,
    action: str,
    confidence: str,
    flags: list[dict[str, str]],
) -> FindingDecisionEvidenceV2:
    priority_value = str(getattr(priority, "value", priority))
    priority_label = priority_value.title()
    decision_statement = (
        f"Decision Statement: remediate {finding.cve_id} on {asset_name} with the "
        "assigned owner before the emergency SLA expires."
    )
    business_impact = (
        f"Executive attention is warranted for {asset_name} because the finding combines "
        f"{priority_label} priority with provider-backed risk signals."
    )
    return FindingDecisionEvidenceV2(
        finding_id=str(finding.id),
        analysis_run_id=str(analysis_run_id),
        project_id=str(project_id),
        cve_id=finding.cve_id,
        dedup_key=finding.dedup_key,
        status=str(finding.status),
        priority=priority_value,
        priority_rank=priority_rank,
        risk_score=risk_score,
        operational_rank=operational_rank,
        in_kev=in_kev,
        epss=epss,
        cvss_base_score=cvss,
        attack_mapped=bool(getattr(finding, "attack_mapped", False)),
        suppressed_by_vex=bool(getattr(finding, "suppressed_by_vex", False)),
        under_investigation=bool(getattr(finding, "under_investigation", False)),
        waived=bool(getattr(finding, "waived", False)),
        rationale=rationale,
        recommended_action=action,
        occurrence_scope={
            "target_ref": asset_key,
            "component_name": component_name,
            "component_version": component_version or None,
            "purl": component_purl,
            "package_type": component_package_type,
        },
        priority_evidence=PriorityEvidenceV2(
            priority_label=priority_label,
            priority_rank=priority_rank,
            operational_score=risk_score,
            operational_score_reasons=[rationale],
            explanation={
                "reasons": [{"code": "seed.provider_signal", "message": rationale}],
                "reason_codes": ["seed.provider_signal"],
            },
            rationale=rationale,
            data_quality_confidence=confidence,
            data_quality_flags=_quality_flags(flags),
            raw={
                "data_quality_confidence": confidence,
                "data_quality_flags": flags,
                "provenance": {
                    "asset_ids": [asset_key],
                    "asset_names": [asset_name],
                    "components": [component_name],
                    "versions": [component_version],
                },
            },
        ),
        provider=ProviderEvidenceV2(
            provider_evidence={"epss": epss, "cvss_base_score": cvss, "in_kev": in_kev},
            epss_hits=1,
            kev_hits=1 if in_kev else 0,
            nvd_hits=1,
        ),
        governance=GovernanceEvidenceV2(
            suppressed_by_vex=bool(getattr(finding, "suppressed_by_vex", False)),
            under_investigation=bool(getattr(finding, "under_investigation", False)),
            waived=bool(getattr(finding, "waived", False)),
            data_quality={"confidence": confidence, "flags": flags},
        ),
        attack=AttackEvidenceV2(),
        remediation=RemediationEvidenceV2(
            recommended_action=action,
            decision_statement=decision_statement,
            recommendation=action,
            recommendation_label="Patch",
            business_impact=business_impact,
            sla={"label": "Emergency", "target_hours": 24},
            raw={
                "decision_statement": decision_statement,
                "recommendation": action,
                "recommendation_label": "Patch",
                "business_impact": {"text": business_impact},
                "sla": {"label": "Emergency", "target_hours": 24},
            },
        ),
    )


def _quality_flags(flags: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        {
            "source": flag.get("source") or "seed",
            "code": flag.get("code") or "seed_flag",
            "message": flag.get("message") or "",
            "severity": flag.get("severity") or "warning",
            **({"cve_id": flag["cve_id"]} if flag.get("cve_id") else {}),
        }
        for flag in flags
    ]
