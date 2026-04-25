"""Response payload helpers for Workbench routes."""

from __future__ import annotations

from typing import Any


def _project_payload(project: Any) -> dict[str, Any]:
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at.isoformat(),
    }


def _asset_payload(asset: Any, *, finding_count: int = 0) -> dict[str, Any]:
    return {
        "id": asset.id,
        "project_id": asset.project_id,
        "asset_id": asset.asset_id,
        "target_ref": asset.target_ref,
        "owner": asset.owner,
        "business_service": asset.business_service,
        "environment": asset.environment,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
        "finding_count": finding_count,
    }


def _analysis_run_payload(run: Any) -> dict[str, Any]:
    attack_summary = run.attack_summary_json if isinstance(run.attack_summary_json, dict) else {}
    return {
        "id": run.id,
        "project_id": run.project_id,
        "input_type": run.input_type,
        "input_filename": run.input_filename,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "error_message": run.error_message,
        "provider_snapshot_id": run.provider_snapshot_id,
        "summary": {
            "findings_count": run.metadata_json.get("findings_count", 0),
            "kev_hits": run.metadata_json.get("kev_hits", 0),
            "counts_by_priority": run.metadata_json.get("counts_by_priority", {}),
            "provider_snapshot_id": run.provider_snapshot_id,
            "provider_snapshot_missing": run.provider_snapshot_id is None
            and bool(run.metadata_json.get("locked_provider_data")),
            "attack_enabled": bool(run.metadata_json.get("attack_enabled", False)),
            "attack_mapped_cves": int(attack_summary.get("mapped_cves", 0)),
            "attack_source": str(run.metadata_json.get("attack_source", "none")),
            "attack_version": run.metadata_json.get("attack_version"),
            "attack_domain": run.metadata_json.get("attack_domain"),
            "attack_mapping_file_sha256": run.metadata_json.get("attack_mapping_file_sha256"),
            "attack_technique_metadata_file_sha256": run.metadata_json.get(
                "attack_technique_metadata_file_sha256"
            ),
            "attack_metadata_format": run.metadata_json.get("attack_metadata_format"),
            "attack_stix_spec_version": run.metadata_json.get("attack_stix_spec_version"),
        },
    }


def _finding_payload(finding: Any, *, include_detail: bool = False) -> dict[str, Any]:
    payload = {
        "id": finding.id,
        "project_id": finding.project_id,
        "analysis_run_id": finding.analysis_run_id,
        "cve_id": finding.cve_id,
        "priority": finding.priority,
        "priority_rank": finding.priority_rank,
        "operational_rank": finding.operational_rank,
        "status": finding.status,
        "in_kev": finding.in_kev,
        "epss": finding.epss,
        "cvss_base_score": finding.cvss_base_score,
        "component": finding.component.name if finding.component else None,
        "component_version": finding.component.version if finding.component else None,
        "asset": finding.asset.asset_id if finding.asset else None,
        "owner": finding.asset.owner if finding.asset else None,
        "service": finding.asset.business_service if finding.asset else None,
        "attack_mapped": finding.attack_mapped,
        "threat_context_rank": _latest_threat_context_rank(finding),
        "suppressed_by_vex": finding.suppressed_by_vex,
        "under_investigation": finding.under_investigation,
        "vex_statuses": _finding_vex_statuses(finding),
        "waived": finding.waived,
        "waiver_status": finding.waiver_status,
        "waiver_reason": finding.waiver_reason,
        "waiver_owner": finding.waiver_owner,
        "waiver_expires_on": finding.waiver_expires_on,
        "waiver_review_on": finding.waiver_review_on,
        "waiver_days_remaining": finding.waiver_days_remaining,
        "waiver_scope": finding.waiver_scope,
        "waiver_id": finding.waiver_id,
        "waiver_matched_scope": finding.waiver_matched_scope,
        "waiver_approval_ref": finding.waiver_approval_ref,
        "waiver_ticket_url": finding.waiver_ticket_url,
        "rationale": finding.rationale,
        "recommended_action": finding.recommended_action,
    }
    if include_detail:
        payload["finding"] = finding.finding_json
        payload["occurrences"] = [item.evidence_json for item in finding.occurrences]
    return payload


def _finding_vex_statuses(finding: Any) -> dict[str, int]:
    raw_provenance = finding.finding_json.get("provenance") if finding.finding_json else {}
    provenance = raw_provenance if isinstance(raw_provenance, dict) else {}
    raw_statuses = provenance.get("vex_statuses")
    if not isinstance(raw_statuses, dict):
        return {}
    statuses: dict[str, int] = {}
    for key, value in raw_statuses.items():
        if not key:
            continue
        try:
            statuses[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return statuses


def _latest_threat_context_rank(finding: Any) -> int | None:
    contexts = getattr(finding, "attack_contexts", None) or []
    if not contexts:
        return None
    return min(int(context.threat_context_rank) for context in contexts)


def _attack_context_payload(context: Any, *, finding_id: str) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "cve_id": context.cve_id,
        "mapped": context.mapped,
        "source": context.source,
        "source_version": context.source_version,
        "source_hash": context.source_hash,
        "source_path": context.source_path,
        "attack_version": context.attack_version,
        "domain": context.domain,
        "metadata_hash": context.metadata_hash,
        "metadata_path": context.metadata_path,
        "attack_relevance": context.attack_relevance,
        "threat_context_rank": context.threat_context_rank,
        "rationale": context.rationale,
        "review_status": context.review_status,
        "techniques": context.techniques_json or [],
        "tactics": context.tactics_json or [],
        "mappings": context.mappings_json or [],
    }


def _governance_payload(summary: Any) -> dict[str, Any]:
    return {
        "total_findings": summary.total_findings,
        "owners": [rollup.to_dict() for rollup in summary.owner_rollups],
        "services": [rollup.to_dict() for rollup in summary.service_rollups],
        "waiver_summary": summary.waiver_lifecycle.to_dict(),
        "vex_summary": summary.vex.to_dict(),
    }


def _project_config_payload(snapshot: Any) -> dict[str, Any]:
    return {
        "id": snapshot.id,
        "project_id": snapshot.project_id,
        "source": snapshot.source,
        "config": snapshot.config_json or {},
        "created_at": snapshot.created_at.isoformat(),
    }


def _report_payload(report: Any) -> dict[str, Any]:
    return {
        "id": report.id,
        "analysis_run_id": report.analysis_run_id,
        "format": report.format,
        "kind": report.kind,
        "sha256": report.sha256,
        "download_url": f"/api/reports/{report.id}/download",
    }


def _evidence_bundle_payload(bundle: Any) -> dict[str, Any]:
    return {
        "id": bundle.id,
        "analysis_run_id": bundle.analysis_run_id,
        "sha256": bundle.sha256,
        "download_url": f"/api/evidence-bundles/{bundle.id}/download",
        "verify_url": f"/api/evidence-bundles/{bundle.id}/verify",
    }
