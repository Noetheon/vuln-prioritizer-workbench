"""Shared Workbench report renderer helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from typing import Any

from app.services.report_contracts import PRIORITY_LABELS
from app.services.report_formatting import dict_value as _dict_value
from app.services.report_models import MarkdownReportFinding, MarkdownReportPayload
from vuln_prioritizer.security_redaction import redact_value


def _redacted_bundle_payload(
    payload: MarkdownReportPayload,
) -> tuple[MarkdownReportPayload, list[str]]:
    redactions: list[str] = []

    def redact(value: Any, path: str) -> Any:
        redacted, paths = _redact_bundle_value(value, path_prefix=path)
        redactions.extend(paths)
        return redacted

    provider_snapshot = None
    if payload.provider_snapshot is not None:
        provider_snapshot = replace(
            payload.provider_snapshot,
            id=redact(payload.provider_snapshot.id, "provider_snapshot.id"),
            content_hash=redact(
                payload.provider_snapshot.content_hash,
                "provider_snapshot.content_hash",
            ),
            nvd_last_sync=redact(
                payload.provider_snapshot.nvd_last_sync,
                "provider_snapshot.nvd_last_sync",
            ),
            epss_date=redact(payload.provider_snapshot.epss_date, "provider_snapshot.epss_date"),
            kev_catalog_version=redact(
                payload.provider_snapshot.kev_catalog_version,
                "provider_snapshot.kev_catalog_version",
            ),
            created_at=redact(payload.provider_snapshot.created_at, "provider_snapshot.created_at"),
            source_hashes=redact(
                payload.provider_snapshot.source_hashes,
                "provider_snapshot.source_hashes",
            ),
            source_metadata=redact(
                payload.provider_snapshot.source_metadata,
                "provider_snapshot.source_metadata",
            ),
        )

    findings: list[MarkdownReportFinding] = []
    for index, finding in enumerate(payload.findings):
        finding_path = f"findings.{index}"
        findings.append(
            replace(
                finding,
                cve_id=redact(finding.cve_id, f"{finding_path}.cve_id"),
                priority=redact(finding.priority, f"{finding_path}.priority"),
                status=redact(finding.status, f"{finding_path}.status"),
                asset=redact(finding.asset, f"{finding_path}.asset"),
                component=redact(finding.component, f"{finding_path}.component"),
                rationale=redact(finding.rationale, f"{finding_path}.rationale"),
                recommended_action=redact(
                    finding.recommended_action,
                    f"{finding_path}.recommended_action",
                ),
                id=redact(finding.id, f"{finding_path}.id"),
                dedup_key=redact(finding.dedup_key, f"{finding_path}.dedup_key"),
                asset_key=redact(finding.asset_key, f"{finding_path}.asset_key"),
                owner=redact(finding.owner, f"{finding_path}.owner"),
                business_service=redact(
                    finding.business_service,
                    f"{finding_path}.business_service",
                ),
                environment=redact(finding.environment, f"{finding_path}.environment"),
                exposure=redact(finding.exposure, f"{finding_path}.exposure"),
                criticality=redact(finding.criticality, f"{finding_path}.criticality"),
                component_purl=redact(finding.component_purl, f"{finding_path}.component_purl"),
                decision_statement=redact(
                    finding.decision_statement,
                    f"{finding_path}.decision_statement",
                ),
                business_impact=redact(
                    finding.business_impact,
                    f"{finding_path}.business_impact",
                ),
                decision_sla=redact(finding.decision_sla, f"{finding_path}.decision_sla"),
                data_quality_flags=redact(
                    finding.data_quality_flags,
                    f"{finding_path}.data_quality_flags",
                ),
                vulnerability=redact(finding.vulnerability, f"{finding_path}.vulnerability"),
                explanation=redact(finding.explanation, f"{finding_path}.explanation"),
                data_quality=redact(finding.data_quality, f"{finding_path}.data_quality"),
                evidence=redact(finding.evidence, f"{finding_path}.evidence"),
                occurrences=redact(finding.occurrences, f"{finding_path}.occurrences"),
            )
        )

    return (
        replace(
            payload,
            project_name=redact(payload.project_name, "project.name"),
            project_description=redact(payload.project_description, "project.description"),
            project_owner_id=redact(payload.project_owner_id, "project.owner_id"),
            input_type=redact(payload.input_type, "analysis_run.input_type"),
            filename=redact(payload.filename, "analysis_run.filename"),
            summary=redact(payload.summary, "analysis_run.summary"),
            run_error=redact(payload.run_error, "analysis_run.error_message"),
            run_errors=redact(payload.run_errors, "analysis_run.errors"),
            governance_rollups=redact(payload.governance_rollups, "governance_rollups"),
            detection_coverage=redact(payload.detection_coverage, "detection_coverage"),
            findings=findings,
            provider_snapshot=provider_snapshot,
        ),
        redactions,
    )


def _redact_bundle_value(value: Any, *, path_prefix: str = "") -> tuple[Any, list[str]]:
    return redact_value(value, path_prefix=path_prefix)


def _counts_by_priority(findings: list[MarkdownReportFinding]) -> dict[str, int]:
    counts = Counter(_priority_label(finding.priority) for finding in findings)
    return {priority: counts.get(priority, 0) for priority in PRIORITY_LABELS}


def _priority_label(value: str) -> str:
    normalized = value.split(".", maxsplit=1)[-1].strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(normalized, "Low")


def _decision_guidance_from_payload(finding: MarkdownReportFinding) -> dict[str, Any]:
    value = finding.explanation.get("decision_guidance")
    return dict(value) if isinstance(value, dict) else {}


def _string_from_mapping(mapping: dict[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _boolish_signal(finding: MarkdownReportFinding, key: str) -> bool:
    if hasattr(finding, key):
        return bool(getattr(finding, key))
    if key == "attack_mapped":
        value: Any = finding.explanation.get(key, False)
        if value is False:
            value = finding.evidence.get(key, False)
    else:
        value = finding.explanation.get(key, False)
    return bool(value)


def _list_value(mapping: dict[str, Any], key: str) -> list[Any]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _vex_statuses_label(finding: MarkdownReportFinding) -> str:
    return _vex_statuses_label_from_explanation(finding.explanation)


def _vex_statuses_label_from_explanation(explanation: dict[str, Any]) -> str:
    status_counts = _vex_status_counts_from_explanation(explanation)
    if status_counts:
        return ";".join(f"{status}:{count}" for status, count in sorted(status_counts.items()))
    return ""


def _vex_status_counts_from_explanation(explanation: dict[str, Any]) -> Counter[str]:
    status_counts: Counter[str] = Counter()
    for record in (explanation, _dict_value(explanation.get("provenance"))):
        statuses = record.get("vex_statuses")
        if isinstance(statuses, dict) and statuses:
            for status, count in statuses.items():
                status_text = str(status).strip()
                if not status_text:
                    continue
                if isinstance(count, int | float):
                    status_counts[status_text] += int(count)
                elif count:
                    status_counts[status_text] += 1
            return status_counts
        status = record.get("vex_status")
        if isinstance(status, str) and status.strip():
            status_counts[status.strip()] += 1
            return status_counts
    return status_counts


def _governance_vex_summary(findings: list[MarkdownReportFinding]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    for finding in findings:
        status_counts.update(_vex_status_counts_from_explanation(finding.explanation))
    return {
        "suppressed_by_vex_count": sum(
            1 for finding in findings if _boolish_signal(finding, "suppressed_by_vex")
        ),
        "under_investigation_count": sum(
            1 for finding in findings if _boolish_signal(finding, "under_investigation")
        ),
        "fixed_count": sum(1 for finding in findings if finding.status.lower().endswith("fixed")),
        "status_counts": dict(sorted(status_counts.items())),
    }


__all__ = [
    "_boolish_signal",
    "_counts_by_priority",
    "_decision_guidance_from_payload",
    "_dict_list",
    "_governance_vex_summary",
    "_list_value",
    "_priority_label",
    "_redact_bundle_value",
    "_redacted_bundle_payload",
    "_string_from_mapping",
    "_vex_status_counts_from_explanation",
    "_vex_statuses_label",
    "_vex_statuses_label_from_explanation",
]
