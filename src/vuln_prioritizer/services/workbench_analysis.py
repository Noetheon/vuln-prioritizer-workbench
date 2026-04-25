"""Workbench import orchestration built on the existing analysis core."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from vuln_prioritizer.cli_support.common import (
    AttackSource,
    InputFormat,
    OutputFormat,
    SortBy,
)
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS
from vuln_prioritizer.db.models import AnalysisRun, ProviderSnapshot
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.inputs.loader import InputSpec
from vuln_prioritizer.models import AnalysisContext, AttackData, PrioritizedFinding, PriorityPolicy
from vuln_prioritizer.provider_snapshot import load_provider_snapshot
from vuln_prioritizer.reporting_payloads import build_analysis_report_payload
from vuln_prioritizer.services.analysis import (
    AnalysisInputError,
    AnalysisNoFindingsError,
    AnalysisRequest,
    prepare_analysis,
)
from vuln_prioritizer.services.workbench_attack import (
    attack_mapping_payload,
    attack_technique_payload,
    confidence_for_source,
    mapping_rationale,
    review_status_for_source,
    threat_context_rank,
    validate_attack_artifact_path,
    validate_workbench_attack_source,
    workbench_mapping_source,
)
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
    attack_source: str = AttackSource.none.value,
    attack_mapping_file: Path | None = None,
    attack_technique_metadata_file: Path | None = None,
    asset_context_file: Path | None = None,
    vex_file: Path | None = None,
    waiver_file: Path | None = None,
) -> WorkbenchImportResult:
    """Analyze an uploaded file and persist the Workbench run."""
    if input_format not in SUPPORTED_WORKBENCH_INPUT_FORMATS:
        raise WorkbenchAnalysisError(f"Unsupported Workbench input format: {input_format}.")

    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise WorkbenchAnalysisError(f"Project not found: {project_id}.")
    _validate_workbench_attack_inputs(
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )

    provider_snapshot = _persist_provider_snapshot(
        repo,
        provider_snapshot_file=provider_snapshot_file,
        locked_provider_data=locked_provider_data,
    )
    run = repo.create_analysis_run(
        project_id=project_id,
        input_type=input_format,
        input_filename=original_filename,
        input_path=str(input_path),
        status="running",
        provider_snapshot_id=provider_snapshot.id if provider_snapshot is not None else None,
    )
    session.flush()

    attack_enabled = attack_source != AttackSource.none.value
    request = AnalysisRequest(
        input_specs=[InputSpec(path=input_path, input_format=input_format)],
        output=None,
        format=OutputFormat.json,
        provider_snapshot_file=provider_snapshot_file,
        locked_provider_data=locked_provider_data,
        no_attack=not attack_enabled,
        attack_source=AttackSource(attack_source),
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
        offline_attack_file=None,
        priority_filters=None,
        kev_only=False,
        min_cvss=None,
        min_epss=None,
        sort_by=SortBy.operational,
        policy=PriorityPolicy(),
        policy_profile="default",
        policy_file=None,
        waiver_file=waiver_file,
        asset_context=asset_context_file,
        target_kind="generic",
        target_ref=None,
        vex_files=[vex_file] if vex_file is not None else [],
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
    except (
        OSError,
        ValidationError,
        ValueError,
        AnalysisInputError,
        AnalysisNoFindingsError,
    ) as exc:
        repo.finish_analysis_run(run.id, status="failed", error_message=str(exc))
        raise WorkbenchAnalysisError(str(exc)) from exc

    payload = build_analysis_report_payload(findings, context)
    _attach_workbench_metadata(
        payload,
        provider_snapshot=provider_snapshot,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
        asset_context_file=asset_context_file,
        vex_file=vex_file,
        waiver_file=waiver_file,
    )
    _persist_findings(repo, run, findings, context=context)
    repo.finish_analysis_run(
        run.id,
        status="completed",
        metadata_json=payload.get("metadata", {}),
        attack_summary_json=payload.get("attack_summary", {}),
        summary_json=payload,
    )
    session.flush()
    return WorkbenchImportResult(run=run, payload=payload)


def _attach_workbench_metadata(
    payload: dict[str, Any],
    *,
    provider_snapshot: ProviderSnapshot | None,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    asset_context_file: Path | None,
    vex_file: Path | None,
    waiver_file: Path | None,
) -> None:
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return
    if provider_snapshot is not None:
        metadata["provider_snapshot_id"] = provider_snapshot.id
        metadata["provider_snapshot_hash"] = provider_snapshot.content_hash
    attack_artifacts: dict[str, dict[str, str | int]] = {}
    for label, path in (
        ("mapping", attack_mapping_file),
        ("technique_metadata", attack_technique_metadata_file),
    ):
        if path is None:
            continue
        content = path.read_bytes()
        attack_artifacts[label] = {
            "path": str(path),
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    if attack_artifacts:
        metadata["attack_artifacts"] = attack_artifacts
    context_artifacts: dict[str, dict[str, str | int]] = {}
    for label, path in (
        ("asset_context", asset_context_file),
        ("vex", vex_file),
        ("waiver", waiver_file),
    ):
        if path is None:
            continue
        content = path.read_bytes()
        context_artifacts[label] = {
            "path": str(path),
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    if context_artifacts:
        metadata["context_artifacts"] = context_artifacts
        if asset_context_file is not None:
            metadata["asset_context_file"] = str(asset_context_file)
        if vex_file is not None:
            metadata["vex_files"] = [str(vex_file)]
        if waiver_file is not None:
            metadata["waiver_file"] = str(waiver_file)


def _persist_findings(
    repo: WorkbenchRepository,
    run: AnalysisRun,
    findings: list[PrioritizedFinding],
    *,
    context: AnalysisContext,
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
            under_investigation=finding.under_investigation,
            waiver_status=finding.waiver_status,
            waiver_reason=finding.waiver_reason,
            waiver_owner=finding.waiver_owner,
            waiver_expires_on=finding.waiver_expires_on,
            waiver_review_on=finding.waiver_review_on,
            waiver_days_remaining=finding.waiver_days_remaining,
            waiver_scope=finding.waiver_scope,
            waiver_id=finding.waiver_id,
            waiver_matched_scope=finding.waiver_matched_scope,
            waiver_approval_ref=finding.waiver_approval_ref,
            waiver_ticket_url=finding.waiver_ticket_url,
            recommended_action=finding.recommended_action,
            rationale=finding.rationale,
            explanation_json=finding_payload,
            finding_json=finding_payload,
            waived=finding.waived,
        )
        _persist_attack_context(
            repo,
            run=run,
            finding_id=persisted.id,
            vulnerability_id=vulnerability.id,
            finding=finding,
            context=context,
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


def _persist_attack_context(
    repo: WorkbenchRepository,
    *,
    run: AnalysisRun,
    finding_id: str,
    vulnerability_id: str,
    finding: PrioritizedFinding,
    context: AnalysisContext,
) -> None:
    source = workbench_mapping_source(context.attack_source if finding.attack_mapped else "none")
    if source != "none":
        validate_workbench_attack_source(source)
    review_status = review_status_for_source(source, mapped=finding.attack_mapped)
    attack = _attack_data_from_finding(finding, source=source, context=context)
    for mapping in finding.attack_mappings:
        repo.upsert_attack_mapping(
            vulnerability_id=vulnerability_id,
            cve_id=finding.cve_id,
            attack_object_id=mapping.attack_object_id,
            attack_object_name=mapping.attack_object_name,
            mapping_type=mapping.mapping_type,
            source=source,
            source_version=context.attack_source_version,
            source_hash=context.attack_mapping_file_sha256,
            source_path=context.attack_mapping_file,
            attack_version=context.attack_version,
            domain=context.attack_domain,
            metadata_hash=context.attack_technique_metadata_file_sha256,
            metadata_path=context.attack_technique_metadata_file,
            confidence=confidence_for_source(source),
            review_status=review_status,
            rationale=mapping_rationale(mapping, attack),
            references_json=mapping.references,
            mapping_json=attack_mapping_payload(mapping),
        )

    repo.create_or_update_finding_attack_context(
        finding_id=finding_id,
        analysis_run_id=run.id,
        cve_id=finding.cve_id,
        mapped=finding.attack_mapped,
        source=source,
        source_version=context.attack_source_version,
        source_hash=context.attack_mapping_file_sha256,
        source_path=context.attack_mapping_file,
        attack_version=context.attack_version,
        domain=context.attack_domain,
        metadata_hash=context.attack_technique_metadata_file_sha256,
        metadata_path=context.attack_technique_metadata_file,
        attack_relevance=finding.attack_relevance,
        threat_context_rank=threat_context_rank(attack),
        rationale=finding.attack_rationale,
        review_status=review_status,
        techniques_json=[
            attack_technique_payload(technique) for technique in finding.attack_technique_details
        ],
        tactics_json=finding.attack_tactics,
        mappings_json=[attack_mapping_payload(mapping) for mapping in finding.attack_mappings],
    )


def _attack_data_from_finding(
    finding: PrioritizedFinding,
    *,
    source: str,
    context: AnalysisContext,
) -> AttackData:
    return AttackData(
        cve_id=finding.cve_id,
        mapped=finding.attack_mapped,
        source=source,
        source_version=context.attack_source_version,
        attack_version=context.attack_version,
        domain=context.attack_domain,
        mappings=finding.attack_mappings,
        techniques=finding.attack_technique_details,
        attack_relevance=finding.attack_relevance,
        attack_rationale=finding.attack_rationale,
        attack_techniques=finding.attack_techniques,
        attack_tactics=finding.attack_tactics,
        attack_note=finding.attack_note,
    )


def _finding_status(finding: PrioritizedFinding) -> str:
    if finding.suppressed_by_vex:
        return "suppressed"
    if finding.waived:
        return "accepted"
    return "open"


def _validate_workbench_attack_inputs(
    *,
    attack_source: str,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
) -> None:
    try:
        normalized_source = AttackSource(attack_source)
    except ValueError as exc:
        raise WorkbenchAnalysisError(
            f"Unsupported Workbench ATT&CK source: {attack_source}."
        ) from exc

    if normalized_source == AttackSource.none:
        if attack_mapping_file is not None or attack_technique_metadata_file is not None:
            raise WorkbenchAnalysisError("ATT&CK mapping files require attack_source=ctid-json.")
        return

    if normalized_source != AttackSource.ctid_json:
        raise WorkbenchAnalysisError(
            "Workbench ATT&CK imports only support ctid-json; local-csv is CLI legacy mode."
        )
    if attack_mapping_file is None:
        raise WorkbenchAnalysisError("ATT&CK ctid-json imports require a mapping file.")

    validate_workbench_attack_source("ctid")
    try:
        validate_attack_artifact_path(attack_mapping_file, label="ATT&CK mapping file")
        if attack_technique_metadata_file is not None:
            validate_attack_artifact_path(
                attack_technique_metadata_file,
                label="ATT&CK technique metadata file",
            )
    except ValueError as exc:
        raise WorkbenchAnalysisError(str(exc)) from exc


def _persist_provider_snapshot(
    repo: WorkbenchRepository,
    *,
    provider_snapshot_file: Path | None,
    locked_provider_data: bool,
) -> ProviderSnapshot | None:
    if provider_snapshot_file is None:
        return None

    try:
        report = load_provider_snapshot(provider_snapshot_file)
    except ValueError as exc:
        if locked_provider_data:
            raise WorkbenchAnalysisError(str(exc)) from exc
        metadata_json: dict[str, Any] = {
            "source_path": str(provider_snapshot_file),
            "locked_provider_data": locked_provider_data,
            "missing": True,
            "validation_error": str(exc),
        }
        return repo.get_or_create_provider_snapshot(
            content_hash=_snapshot_content_hash(provider_snapshot_file),
            metadata_json=metadata_json,
        )

    epss_dates = sorted(
        {
            item.epss.date
            for item in report.items
            if item.epss is not None and item.epss.date is not None
        }
    )
    kev_dates = sorted(
        {
            item.kev.date_added
            for item in report.items
            if item.kev is not None and item.kev.date_added is not None
        }
    )
    nvd_dates = sorted(
        {
            item.nvd.last_modified
            for item in report.items
            if item.nvd is not None and item.nvd.last_modified is not None
        }
    )
    metadata_json = report.metadata.model_dump()
    metadata_json.update(
        {
            "source_path": str(provider_snapshot_file),
            "locked_provider_data": locked_provider_data,
            "item_count": len(report.items),
            "warnings": report.warnings,
            "missing": False,
        }
    )
    return repo.get_or_create_provider_snapshot(
        content_hash=_snapshot_content_hash(provider_snapshot_file),
        nvd_last_sync=nvd_dates[-1] if nvd_dates else None,
        epss_date=epss_dates[-1] if epss_dates else None,
        kev_catalog_version=kev_dates[-1] if kev_dates else None,
        metadata_json=metadata_json,
    )


def _snapshot_content_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return f"unreadable:{path}"
