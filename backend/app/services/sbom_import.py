"""Bridge isolated SBOM scanning to the existing decision import pipeline."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path

from app.contracts.sbom import SbomAssessmentV1
from app.core.config import Settings
from app.domain.engine.inputs._occurrence_support import finalize_occurrences
from app.domain.engine.inputs.parsers.scanner import parse_grype_json
from app.domain.engine.models import AnalysisContext
from app.importers import ImporterParseError
from app.importers.input_loader_adapter import normalize_parsed_input
from app.services.analysis import WorkbenchAnalysisResult
from app.services.import_execution_parsing import ParsedPreparedUpload
from app.services.import_execution_types import PreparedImportUpload, StoredImportArtifacts
from app.services.import_uploads import sanitize_parser_error_message
from app.services.sbom_scanner import SbomScannerError, scan_sbom
from app.services.workflow_execution import WorkflowExecutionContext


def _public_warnings(messages: Iterable[str]) -> list[str]:
    """Keep run evidence bounded while retaining the complete scanner report."""
    warnings: list[str] = []
    omitted = 0
    for message in messages:
        sanitized = sanitize_parser_error_message(message)
        if len(sanitized) > 1000:
            sanitized = sanitized[:997] + "..."
        if sanitized in warnings:
            continue
        if len(warnings) < 20:
            warnings.append(sanitized)
        else:
            omitted += 1
    if omitted:
        warnings.append(
            f"{omitted} additional warning(s) omitted; the full scanner report is retained."
        )
    return warnings


def scan_prepared_sbom(
    prepared: PreparedImportUpload,
    artifacts: StoredImportArtifacts,
    *,
    settings: Settings,
    context: WorkflowExecutionContext,
    observed_at: datetime,
) -> tuple[ParsedPreparedUpload, SbomAssessmentV1]:
    """Retain immutable source/report artifacts and normalize completed scan results."""
    context.stage("scan_sbom", "Matching SBOM components against the local Grype database.")
    try:
        result = scan_sbom(
            artifacts.upload_path,
            executable=settings.SBOM_GRYPE_EXECUTABLE,
            cache_dir=settings.provider_cache_dir_path / "grype",
            target_ref=prepared.sbom_target_ref,
            timeout_seconds=settings.SBOM_SCAN_TIMEOUT_SECONDS,
            max_output_bytes=settings.SBOM_SCAN_MAX_OUTPUT_MB * 1024 * 1024,
            db_auto_update=prepared.sbom_db_update,
            checkpoint=context.checkpoint,
        )
    except SbomScannerError as exc:
        raise ImporterParseError(str(exc)) from exc
    context.checkpoint()
    if result.evidence.input_sha256 != prepared.upload_sha256:
        raise ImporterParseError("The stored SBOM changed before scanning; import it again.")
    if result.evidence.input_format != prepared.input_type:
        raise ImporterParseError(
            "The selected SBOM input type does not match the uploaded document."
        )
    # Attempt-specific storage keeps retries from overwriting earlier scanner evidence.
    directory = artifacts.upload_path.parent / "sbom-assessments" / str(uuid.uuid4())
    directory.mkdir(parents=True, exist_ok=False)
    report_path = directory / "grype-report.json"
    report_path.write_bytes(result.report_bytes)
    manifest_path = directory / "assessment.json"
    upload_root = settings.import_upload_dir_path.resolve()
    raw = parse_grype_json(report_path)
    warnings = _public_warnings(chain(result.evidence.warnings, raw.warnings))
    observation = (
        observed_at.replace(tzinfo=UTC)
        if observed_at.tzinfo is None
        else observed_at.astimezone(UTC)
    )
    assessment = result.evidence.model_copy(
        update={
            "observed_at": prepared.sbom_observed_at or observation.isoformat(),
            "warnings": warnings,
            "status": "partial" if warnings else result.evidence.status,
            "source_run_id": prepared.sbom_source_run_id,
            "artifact_refs": {
                "input": artifacts.upload_ref,
                "report": report_path.relative_to(upload_root).as_posix(),
                "manifest": manifest_path.relative_to(upload_root).as_posix(),
            },
        }
    )
    manifest_path.write_text(assessment.model_dump_json(indent=2), encoding="utf-8")
    normalized = finalize_occurrences(
        [
            item.model_copy(update={"target_kind": "sbom", "target_ref": assessment.target_ref})
            for item in raw.occurrences
        ],
        input_format=prepared.input_type,
        warnings=warnings,
        total_rows=raw.total_rows,
        max_cves=None,
        input_paths=[str(artifacts.upload_path)],
        allow_empty=True,
    )
    parsed = normalize_parsed_input(normalized, input_type="grype-json")
    return ParsedPreparedUpload(occurrences=parsed.occurrences, parsed_input=parsed), assessment


def empty_sbom_analysis(
    *,
    input_path: Path,
    assessment: SbomAssessmentV1,
) -> WorkbenchAnalysisResult:
    """A completed scan without CVE mappings needs no vulnerability-provider requests."""
    return WorkbenchAnalysisResult(
        findings_by_cve={},
        context=AnalysisContext(
            input_path=str(input_path),
            output_format="json",
            generated_at=datetime.now(UTC).isoformat(),
            input_format=assessment.input_format,
            warnings=assessment.warnings,
            total_input=assessment.scanner_match_count,
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )
