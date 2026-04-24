"""Workbench import orchestration built on the existing analysis core."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from pydantic import ValidationError
from sqlalchemy.orm import Session

from vuln_prioritizer.cli_support.analysis import AnalysisRequest, prepare_analysis
from vuln_prioritizer.cli_support.common import (
    AttackSource,
    InputFormat,
    OutputFormat,
    SortBy,
)
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS
from vuln_prioritizer.db.models import AnalysisRun
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.inputs.loader import InputSpec
from vuln_prioritizer.models import PrioritizedFinding, PriorityPolicy
from vuln_prioritizer.reporting_payloads import build_analysis_report_payload
from vuln_prioritizer.workbench_config import WorkbenchSettings

SUPPORTED_WORKBENCH_INPUT_FORMATS = {
    InputFormat.cve_list.value,
    InputFormat.generic_occurrence_csv.value,
    InputFormat.trivy_json.value,
    InputFormat.grype_json.value,
}


class WorkbenchAnalysisError(RuntimeError):
    """Raised when a Workbench import cannot be analyzed."""


@dataclass(frozen=True, slots=True)
class WorkbenchImportResult:
    run: AnalysisRun
    payload: dict[str, Any]


def run_workbench_import(
    *,
    session: Session,
    settings: WorkbenchSettings,
    project_id: str,
    input_path: Path,
    original_filename: str,
    input_format: str,
    provider_snapshot_file: Path | None = None,
    locked_provider_data: bool = False,
) -> WorkbenchImportResult:
    """Analyze an uploaded file and persist the Workbench run."""
    if input_format not in SUPPORTED_WORKBENCH_INPUT_FORMATS:
        raise WorkbenchAnalysisError(f"Unsupported Workbench input format: {input_format}.")

    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise WorkbenchAnalysisError(f"Project not found: {project_id}.")

    run = repo.create_analysis_run(
        project_id=project_id,
        input_type=input_format,
        input_filename=original_filename,
        input_path=str(input_path),
        status="running",
    )
    session.flush()

    request = AnalysisRequest(
        input_specs=[InputSpec(path=input_path, input_format=input_format)],
        output=None,
        format=OutputFormat.json,
        provider_snapshot_file=provider_snapshot_file,
        locked_provider_data=locked_provider_data,
        no_attack=True,
        attack_source=AttackSource.none,
        attack_mapping_file=None,
        attack_technique_metadata_file=None,
        offline_attack_file=None,
        priority_filters=None,
        kev_only=False,
        min_cvss=None,
        min_epss=None,
        sort_by=SortBy.operational,
        policy=PriorityPolicy(),
        policy_profile="default",
        policy_file=None,
        waiver_file=None,
        asset_context=None,
        target_kind="generic",
        target_ref=None,
        vex_files=[],
        show_suppressed=True,
        hide_waived=False,
        fail_on_provider_error=False,
        max_cves=None,
        offline_kev_file=None,
        nvd_api_key_env=settings.nvd_api_key_env,
        no_cache=False,
        cache_dir=settings.provider_cache_dir,
        cache_ttl_hours=DEFAULT_CACHE_TTL_HOURS,
    )

    try:
        findings, context = prepare_analysis(request)
    except (OSError, ValidationError, ValueError) as exc:
        repo.finish_analysis_run(run.id, status="failed", error_message=str(exc))
        raise WorkbenchAnalysisError(str(exc)) from exc
    except typer.Exit as exc:
        detail = f"Analysis failed with exit code {exc.exit_code}."
        repo.finish_analysis_run(run.id, status="failed", error_message=detail)
        raise WorkbenchAnalysisError(detail) from exc

    payload = build_analysis_report_payload(findings, context)
    _persist_findings(repo, run, findings)
    repo.finish_analysis_run(
        run.id,
        status="completed",
        metadata_json=payload.get("metadata", {}),
        attack_summary_json=payload.get("attack_summary", {}),
        summary_json=payload,
    )
    session.flush()
    return WorkbenchImportResult(run=run, payload=payload)


def _persist_findings(
    repo: WorkbenchRepository,
    run: AnalysisRun,
    findings: list[PrioritizedFinding],
) -> None:
    for finding in findings:
        finding_payload = finding.model_dump()
        first_occurrence = (
            finding.provenance.occurrences[0] if finding.provenance.occurrences else None
        )
        component = None
        if first_occurrence and first_occurrence.component_name:
            component = repo.upsert_component(
                name=first_occurrence.component_name,
                version=first_occurrence.component_version,
                purl=first_occurrence.purl,
                ecosystem=first_occurrence.package_type,
                package_type=first_occurrence.package_type,
            )

        asset = None
        if first_occurrence and first_occurrence.asset_id:
            asset = repo.upsert_asset(
                project_id=run.project_id,
                asset_id=first_occurrence.asset_id,
                target_ref=first_occurrence.target_ref,
                owner=first_occurrence.asset_owner,
                business_service=first_occurrence.asset_business_service,
                environment=first_occurrence.asset_environment,
                exposure=first_occurrence.asset_exposure,
                criticality=first_occurrence.asset_criticality,
            )

        provider_evidence = finding.provider_evidence
        nvd = provider_evidence.nvd if provider_evidence else None
        vulnerability = repo.upsert_vulnerability(
            cve_id=finding.cve_id,
            source_id=finding.cve_id,
            title=finding.cve_id,
            description=finding.description,
            cvss_score=finding.cvss_base_score,
            cvss_vector=nvd.cvss_vector if nvd else None,
            severity=finding.cvss_severity,
            cwe=", ".join(nvd.cwes) if nvd and nvd.cwes else None,
            published_at=nvd.published if nvd else None,
            modified_at=nvd.last_modified if nvd else None,
            provider_json=provider_evidence.model_dump() if provider_evidence else {},
        )

        persisted = repo.create_or_update_finding(
            project_id=run.project_id,
            analysis_run_id=run.id,
            vulnerability_id=vulnerability.id,
            cve_id=finding.cve_id,
            component_id=component.id if component else None,
            asset_id=asset.id if asset else None,
            status=_finding_status(finding),
            priority=finding.priority_label,
            priority_rank=finding.priority_rank,
            operational_rank=finding.operational_rank,
            in_kev=finding.in_kev,
            epss=finding.epss,
            cvss_base_score=finding.cvss_base_score,
            attack_mapped=finding.attack_mapped,
            suppressed_by_vex=finding.suppressed_by_vex,
            recommended_action=finding.recommended_action,
            rationale=finding.rationale,
            explanation_json=finding_payload,
            finding_json=finding_payload,
            waived=finding.waived,
        )

        for index, occurrence in enumerate(finding.provenance.occurrences, start=1):
            repo.add_finding_occurrence(
                finding_id=persisted.id,
                analysis_run_id=run.id,
                scanner=occurrence.source_format,
                raw_reference=occurrence.source_record_id or f"{occurrence.source_format}:{index}",
                fix_version=", ".join(occurrence.fix_versions) if occurrence.fix_versions else None,
                evidence_json=occurrence.model_dump(),
            )


def _finding_status(finding: PrioritizedFinding) -> str:
    if finding.suppressed_by_vex:
        return "suppressed"
    if finding.waived:
        return "accepted"
    return "open"
