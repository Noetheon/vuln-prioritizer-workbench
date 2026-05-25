"""Executive report view-model assembly."""

from __future__ import annotations

from app.services.report_html_attack_context import _reviewed_attack_mapping_rows_for_findings
from app.services.report_html_campaign_model import (
    _business_service_view_rows,
    _campaign_requires_emergency,
    _get_remediation_campaigns_helper,
    _recommendation_view_rows,
)
from app.services.report_html_campaign_rendering import _executive_verdict_summary_helper
from app.services.report_html_common import (
    _actionability_counts_helper,
    _count_findings,
    _is_actionable_finding,
    _is_overdue_helper,
    _is_under_investigation_finding,
    _pluralize,
)
from app.services.report_html_decision import (
    _action_plan_rows_helper,
    _decision_needed_statement_helper,
)
from app.services.report_html_evidence_package import (
    _evidence_bundle_status_label,
    _evidence_package_rows_helper,
)
from app.services.report_html_provider_freshness import (
    _provider_freshness_rows_helper,
    _provider_freshness_status_helper,
)
from app.services.report_models import (
    EvidencePackageContext,
    ExecutiveReportViewModel,
    MarkdownReportPayload,
)
from app.services.report_renderer_common import _dict_list


def build_executive_report_view_model(
    payload: MarkdownReportPayload,
    *,
    evidence_package_context: EvidencePackageContext | None = None,
) -> ExecutiveReportViewModel:
    """Prepare the decision-oriented executive report model before rendering."""
    generated_at = payload.generated_at
    snapshot = payload.provider_snapshot
    campaigns = _get_remediation_campaigns_helper(
        payload.findings, project_name=payload.project_name
    )
    actionability = _actionability_counts_helper(payload.findings)
    waiver_debt = payload.governance_rollups.get("waiver_debt", {})
    waiver_items = _dict_list(waiver_debt.get("items"))
    overdue_count = sum(
        1
        for item in waiver_items
        if _is_overdue_helper(str(item.get("review_at") or ""), generated_at)
    )
    review_due_or_expiring = max(
        int(waiver_debt.get("review_due_count") or 0)
        + int(waiver_debt.get("expiring_soon_count") or 0),
        overdue_count,
    )
    emergency_campaigns = [
        campaign for campaign in campaigns if _campaign_requires_emergency(campaign)
    ]
    provider_freshness = _provider_freshness_status_helper(
        snapshot,
        generated_at,
        evidence_package_context,
    )
    reviewed_attack_rows = _reviewed_attack_mapping_rows_for_findings(payload.findings)
    has_governance = bool(payload.governance_rollups)
    business_services = _business_service_view_rows(payload.findings, campaigns)
    recommendations = _recommendation_view_rows(campaigns)
    decision_needed = _decision_needed_statement_helper(
        campaigns,
        provider_freshness=provider_freshness,
        review_due_or_expiring=review_due_or_expiring,
    )
    open_campaigns = [campaign for campaign in campaigns if campaign["actionable_count"] > 0]
    owner_gap_count = sum(1 for campaign in open_campaigns if not campaign["owners"])
    evidence_bundle_status = _evidence_bundle_status_label(evidence_package_context)
    return ExecutiveReportViewModel(
        report_identity={
            "report_type": "Executive HTML",
            "project_id": payload.project_id,
            "project_name": payload.project_name,
            "analysis_run_id": payload.run_id,
            "generated_at": generated_at,
            "run_status": payload.run_status,
            "input_type": payload.input_type,
            "input_file": payload.filename,
            "provider_snapshot_id": snapshot.id if snapshot else None,
        },
        decision_brief={
            "decision_needed": decision_needed,
            "executive_summary": _executive_verdict_summary_helper(payload),
            "management_approval_items": [
                f"{_pluralize(len(emergency_campaigns), 'emergency remediation campaign')}."
                if emergency_campaigns
                else (
                    f"{_pluralize(len(open_campaigns), 'open remediation campaign')} "
                    "remediation window."
                ),
                "Named owners for each remediation cluster.",
                "Validation evidence after clean re import.",
            ],
            "caution_items": [
                f"Provider snapshot freshness is {provider_freshness.lower()} for formal sign off.",
                (
                    f"{_pluralize(owner_gap_count, 'open campaign')} "
                    f"{'has' if owner_gap_count == 1 else 'have'} no named owner."
                )
                if owner_gap_count
                else "Open campaigns have named owners in the evidence.",
                "Accepted risk, VEX suppressed and fixed findings remain visible as evidence.",
            ],
            "validation_items": [
                "Clean re import after remediation.",
                "Updated fixed evidence for closed findings.",
                "Evidence ZIP manifest and hashes retained for audit review.",
            ],
        },
        risk_posture={
            "total_findings": len(payload.findings),
            "open_actionable_findings": actionability.get("open", 0),
            "kev_backed_findings": _count_findings(
                payload.findings, lambda finding: finding.in_kev
            ),
            "emergency_sla_count": len(emergency_campaigns),
            "accepted_risk_findings": actionability.get("accepted", 0),
            "vex_suppressed_findings": actionability.get("suppressed", 0),
            "fixed_evidence_findings": actionability.get("fixed", 0),
            "review_due_or_expiring_count": review_due_or_expiring,
            "internet_facing_prod_count": _count_findings(
                payload.findings,
                lambda finding: (
                    _is_actionable_finding(finding)
                    and (finding.exposure or "").lower() in {"internet-facing", "external"}
                    and (finding.environment or "").lower() in {"prod", "production"}
                ),
            ),
            "unique_cves_count": len({finding.cve_id for finding in payload.findings}),
            "provider_freshness_verdict": provider_freshness,
            "evidence_bundle_status": evidence_bundle_status,
        },
        action_plan=_action_plan_rows_helper(payload),
        remediation_campaigns=campaigns,
        business_services=business_services,
        governance_exceptions={
            "waiver_rows": waiver_items,
            "waivers": int(waiver_debt.get("waiver_count") or 0),
            "expired": int(waiver_debt.get("expired_count") or 0),
            "review_due": int(waiver_debt.get("review_due_count") or 0),
            "expiring_soon": int(waiver_debt.get("expiring_soon_count") or 0),
            "accepted_findings": actionability.get("accepted", 0),
            "vex_suppressed": actionability.get("suppressed", 0),
            "fixed_findings": actionability.get("fixed", 0),
            "under_investigation": _count_findings(
                payload.findings,
                _is_under_investigation_finding,
            ),
        },
        evidence_confidence={
            "provider_freshness_verdict": provider_freshness,
            "provider_rows": _provider_freshness_rows_helper(
                snapshot,
                generated_at,
                evidence_package_context,
            ),
            "snapshot_replay_status": "Reproducible" if snapshot else "Not available",
            "source_hashes": dict(snapshot.source_hashes) if snapshot else {},
            "static_html_safety_status": "Controlled",
        },
        evidence_package=_evidence_package_rows_helper(
            has_attack_layer=bool(reviewed_attack_rows),
            has_governance=has_governance,
            evidence_package_context=evidence_package_context,
        ),
        recommendations=recommendations,
        attack_context={
            "mapped_techniques": reviewed_attack_rows,
            "mapping_source": sorted({row["source"] for row in reviewed_attack_rows}),
            "navigator_layer_status": "Included in Evidence ZIP"
            if reviewed_attack_rows
            else "Optional / not generated",
            "unmapped_handling_note": "Unmapped CVEs remain unmapped.",
            "no_llm_inference_note": "No LLM inferred mappings are used.",
        },
        technical_appendix={
            "note": (
                "Detailed finding rows, component versions, long remediation text, input "
                "provenance, full rationale and per finding actions remain in the Technical "
                "Markdown report, Analysis JSON, Findings CSV, SARIF and Evidence ZIP."
            )
        },
    )


__all__ = [
    "build_executive_report_view_model",
]
