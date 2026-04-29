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
        "job_id": run.metadata_json.get("job_id") if isinstance(run.metadata_json, dict) else None,
        "summary": {
            "findings_count": run.metadata_json.get("findings_count", 0),
            "kev_hits": run.metadata_json.get("kev_hits", 0),
            "counts_by_priority": run.metadata_json.get("counts_by_priority", {}),
            "provider_snapshot_id": run.provider_snapshot_id,
            "provider_snapshot_missing": run.provider_snapshot_id is None
            and bool(run.metadata_json.get("locked_provider_data")),
            "provider_data_quality_flags": run.metadata_json.get("provider_data_quality_flags", {}),
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
            "defensive_context_sources": run.metadata_json.get("defensive_context_sources", []),
            "defensive_context_hits": run.metadata_json.get("defensive_context_hits", 0),
            "lifecycle_status": run.metadata_json.get("lifecycle_status"),
            "input_uploads": run.metadata_json.get("input_uploads", []),
            "parse_errors": run.metadata_json.get("parse_errors", []),
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
        "data_quality_flags": _finding_data_quality_flags(finding),
        "data_quality_confidence": _finding_data_quality_confidence(finding),
        "provider_evidence": _finding_provider_evidence(finding),
        "defensive_contexts": _finding_defensive_contexts(finding),
    }
    if include_detail:
        payload["finding"] = finding.finding_json
        payload["kev_detail"] = _finding_kev_detail(finding)
        payload["occurrences"] = [item.evidence_json for item in finding.occurrences]
        payload["status_history"] = [
            _finding_status_history_payload(item) for item in getattr(finding, "status_history", [])
        ]
    return payload


def _finding_data_quality_flags(finding: Any) -> list[dict[str, Any]]:
    raw_finding = finding.finding_json if isinstance(finding.finding_json, dict) else {}
    flags = raw_finding.get("data_quality_flags")
    return flags if isinstance(flags, list) else []


def _finding_data_quality_confidence(finding: Any) -> str:
    raw_finding = finding.finding_json if isinstance(finding.finding_json, dict) else {}
    confidence = raw_finding.get("data_quality_confidence")
    return str(confidence) if confidence else "high"


def _finding_provider_evidence(finding: Any) -> dict[str, Any] | None:
    raw_finding = finding.finding_json if isinstance(finding.finding_json, dict) else {}
    provider_evidence = raw_finding.get("provider_evidence")
    if isinstance(provider_evidence, dict):
        return provider_evidence
    vulnerability = getattr(finding, "vulnerability", None)
    provider_json = getattr(vulnerability, "provider_json", None)
    return provider_json if isinstance(provider_json, dict) else None


def _finding_kev_detail(finding: Any) -> dict[str, Any] | None:
    raw_finding = finding.finding_json if isinstance(finding.finding_json, dict) else {}
    evidence = raw_finding.get("provider_evidence")
    kev = evidence.get("kev") if isinstance(evidence, dict) else None
    if not isinstance(kev, dict):
        vulnerability = getattr(finding, "vulnerability", None)
        provider_json = getattr(vulnerability, "provider_json", None)
        kev = provider_json.get("kev") if isinstance(provider_json, dict) else None
    if not isinstance(kev, dict):
        return None

    allowed_keys = {
        "cve_id",
        "in_kev",
        "vendor_project",
        "product",
        "vulnerability_name",
        "short_description",
        "date_added",
        "required_action",
        "due_date",
        "known_ransomware_campaign_use",
        "notes",
    }
    detail = {key: kev.get(key) for key in allowed_keys if key in kev}
    detail.setdefault("cve_id", finding.cve_id)
    detail.setdefault("in_kev", bool(finding.in_kev))
    return detail


def _finding_status_history_payload(item: Any) -> dict[str, Any]:
    return {
        "id": item.id,
        "finding_id": item.finding_id,
        "previous_status": item.previous_status,
        "new_status": item.new_status,
        "actor": item.actor,
        "reason": item.reason,
        "created_at": item.created_at.isoformat(),
    }


def _api_token_payload(token: Any) -> dict[str, Any]:
    return {
        "id": token.id,
        "name": token.name,
        "created_at": token.created_at.isoformat(),
        "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
        "revoked_at": token.revoked_at.isoformat() if token.revoked_at else None,
        "active": token.revoked_at is None,
    }


def _audit_event_payload(event: Any) -> dict[str, Any]:
    return {
        "id": event.id,
        "project_id": event.project_id,
        "event_type": event.event_type,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "actor": event.actor,
        "message": event.message,
        "metadata": event.metadata_json or {},
        "created_at": event.created_at.isoformat(),
    }


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


def _finding_defensive_contexts(finding: Any) -> list[dict[str, Any]]:
    raw_contexts = finding.finding_json.get("defensive_contexts") if finding.finding_json else []
    if not isinstance(raw_contexts, list):
        return []
    return [item for item in raw_contexts if isinstance(item, dict)]


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


def _attack_review_queue_item_payload(context: Any) -> dict[str, Any]:
    finding = context.finding
    techniques = [item for item in (context.techniques_json or []) if isinstance(item, dict)]
    mappings = [item for item in (context.mappings_json or []) if isinstance(item, dict)]
    technique_ids = sorted(
        {
            str(item.get("attack_object_id") or item.get("technique_id"))
            for item in techniques
            if item.get("attack_object_id") or item.get("technique_id")
        }
    )
    mapping_sources = sorted(
        {
            str(item.get("source") or context.source)
            for item in mappings
            if item.get("source") or context.source
        }
    )
    return {
        "finding_id": finding.id,
        "cve_id": context.cve_id,
        "priority": finding.priority,
        "finding_status": finding.status,
        "mapped": context.mapped,
        "source": context.source,
        "source_version": context.source_version,
        "source_hash": context.source_hash,
        "source_path": context.source_path,
        "metadata_hash": context.metadata_hash,
        "metadata_path": context.metadata_path,
        "attack_relevance": context.attack_relevance,
        "threat_context_rank": context.threat_context_rank,
        "review_status": context.review_status,
        "rationale": context.rationale,
        "technique_ids": technique_ids,
        "tactic_names": list(context.tactics_json or []),
        "mapping_count": len(mappings),
        "mapping_sources": mapping_sources,
        "created_at": context.created_at.isoformat(),
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


def _workbench_job_payload(job: Any) -> dict[str, Any]:
    return {
        "id": job.id,
        "project_id": job.project_id,
        "kind": job.kind,
        "status": job.status,
        "target_type": job.target_type,
        "target_id": job.target_id,
        "progress": job.progress,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "priority": job.priority,
        "idempotency_key": job.idempotency_key,
        "payload": job.payload_json or {},
        "result": job.result_json or {},
        "logs": job.logs_json or [],
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat(),
        "queued_at": job.queued_at.isoformat() if job.queued_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "heartbeat_at": job.heartbeat_at.isoformat() if job.heartbeat_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


def _artifact_retention_payload(retention: Any, *, project_id: str) -> dict[str, Any]:
    return {
        "project_id": project_id,
        "report_retention_days": retention.report_retention_days if retention else None,
        "evidence_retention_days": retention.evidence_retention_days if retention else None,
        "max_disk_usage_mb": retention.max_disk_usage_mb if retention else None,
        "updated_at": retention.updated_at.isoformat() if retention else None,
    }


def _detection_control_history_payload(history: Any) -> dict[str, Any]:
    return {
        "id": history.id,
        "project_id": history.project_id,
        "control_id": history.control_id,
        "event_type": history.event_type,
        "actor": history.actor,
        "reason": history.reason,
        "previous": history.previous_json or {},
        "current": history.current_json or {},
        "created_at": history.created_at.isoformat(),
    }


def _detection_control_attachment_payload(attachment: Any) -> dict[str, Any]:
    return {
        "id": attachment.id,
        "project_id": attachment.project_id,
        "control_id": attachment.control_id,
        "filename": attachment.filename,
        "content_type": attachment.content_type,
        "sha256": attachment.sha256,
        "size_bytes": attachment.size_bytes,
        "created_at": attachment.created_at.isoformat(),
        "download_url": f"/api/detection-control-attachments/{attachment.id}/download",
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
