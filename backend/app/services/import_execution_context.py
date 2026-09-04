"""Parse, asset-context, and VEX stages for Workbench import execution."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.ledger import DecisionLedgerInvariantError
from app.domain.asset_identity import (
    is_legacy_reserved_asset_storage_key,
    is_reserved_asset_storage_key,
    is_versioned_asset_identity_key,
    legacy_reserved_asset_storage_key,
    normalize_asset_identity_value,
    normalize_asset_target_kind,
)
from app.domain.component_identity import component_storage_key
from app.domain.engine.inputs._occurrence_support import apply_asset_context, finalize_occurrences
from app.domain.engine.inputs._vex_support import apply_vex_statements
from app.domain.engine.inputs.loader import load_asset_context_file, load_vex_files
from app.domain.engine.models import InputSourceSummary, ParsedInput
from app.domain.import_asset_context import (
    input_occurrence_from_workbench_occurrence as _input_occurrence_from_workbench_occurrence,
)
from app.domain.import_asset_context import (
    workbench_occurrence_with_asset_context as _workbench_occurrence_with_asset_context,
)
from app.domain.import_asset_context import (
    workbench_occurrence_with_vex as _workbench_occurrence_with_vex,
)
from app.importers.contracts import NormalizedOccurrence
from app.models import Asset
from app.repositories.assets import AssetRepository
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.services.import_execution_dedup import (
    _asset_persistence_key,
    _dedup_key_parts,
    _finding_dedup_key,
)
from app.services.import_execution_parsing import summary_warnings as _summary_warnings
from app.services.import_execution_persistence_queries import (
    LegacyFindingIdentity,
    PersistedFindingAssetContext,
    _existing_assets_by_key,
    _existing_components_by_identity_key,
    _existing_finding_asset_context_by_dedup_key,
    _existing_vulnerabilities_by_cve,
    _legacy_finding_identity_lookup,
    _project_has_findings,
)
from app.services.import_uploads import (
    sanitize_parser_error_message as _sanitize_parser_error_message,
)

_PERSISTED_ASSET_CONTEXT_SOURCE = "persisted-project"
_PROJECTION_BATCH_SIZE = 500


class PersistedAssetContextInvariantError(DecisionLedgerInvariantError):
    """Raised when persisted legacy scope evidence cannot be selected safely."""


def _apply_workbench_asset_context(
    occurrences: list[NormalizedOccurrence],
    *,
    asset_context_path: Path,
) -> tuple[list[NormalizedOccurrence], dict[str, Any]]:
    catalog, load_diagnostics = load_asset_context_file(
        asset_context_path,
        return_diagnostics=True,
    )
    input_occurrences = [
        _input_occurrence_from_workbench_occurrence(occurrence) for occurrence in occurrences
    ]
    enriched_occurrences, match_diagnostics = apply_asset_context(
        input_occurrences,
        catalog,
        return_diagnostics=True,
    )
    return (
        [
            _workbench_occurrence_with_asset_context(original, enriched)
            for original, enriched in zip(occurrences, enriched_occurrences, strict=True)
        ],
        {
            "total_rows": load_diagnostics.total_rows,
            "loaded_rows": load_diagnostics.loaded_rows,
            "skipped_rows": load_diagnostics.skipped_rows,
            "exact_rules": load_diagnostics.exact_rules,
            "contains_rules": load_diagnostics.contains_rules,
            "regex_rules": load_diagnostics.regex_rules,
            "glob_rules": load_diagnostics.glob_rules,
            "matched_occurrences": match_diagnostics.matched_occurrences,
            "unmatched_occurrences": match_diagnostics.unmatched_occurrences,
            "ambiguous_occurrences": match_diagnostics.ambiguous_occurrences,
            "warnings": [
                *load_diagnostics.warnings,
                *match_diagnostics.warnings,
            ],
        },
    )


def _apply_persisted_project_asset_context(
    occurrences: list[NormalizedOccurrence],
    *,
    session: Session,
    project_id: uuid.UUID,
) -> list[NormalizedOccurrence]:
    """
    Fill missing analysis context from the current persisted finding scope.

    Explicit values in the primary upload or current sidecar always win. Relational
    asset fields provide mutable project context, while a canonical ``asset_id`` is
    accepted only from the typed current decision projection.
    """
    if not occurrences:
        return occurrences

    dedup_parts = [_dedup_key_parts(project_id, occurrence) for occurrence in occurrences]
    dedup_keys = [_finding_dedup_key(parts) for parts in dedup_parts]
    contexts_by_key: dict[str, PersistedFindingAssetContext] = {}
    if _project_has_findings(session=session, project_id=project_id):
        contexts_by_key = _existing_finding_asset_context_by_dedup_key(
            session=session,
            project_id=project_id,
            dedup_keys=dedup_keys,
        )
        contexts_by_key.update(
            _legacy_asset_contexts_by_current_dedup_key(
                occurrences,
                dedup_parts=dedup_parts,
                dedup_keys=dedup_keys,
                exact_contexts_by_key=contexts_by_key,
                session=session,
                project_id=project_id,
            )
        )
    explicit_assets_by_identity = _existing_assets_by_explicit_import_identity(
        occurrences,
        session=session,
        project_id=project_id,
    )
    if not contexts_by_key and not explicit_assets_by_identity:
        return occurrences

    projection_records = [
        context.current_projection
        for context in contexts_by_key.values()
        if context.current_projection is not None
    ]
    current_evidence_by_finding: dict[uuid.UUID, FindingDecisionEvidenceV2] = {}
    projection_repo = FindingCurrentProjectionRepository(session)
    try:
        for index in range(0, len(projection_records), _PROJECTION_BATCH_SIZE):
            current_evidence_by_finding.update(
                projection_repo.evidence_for_records(
                    projection_records[index : index + _PROJECTION_BATCH_SIZE]
                )
            )
    except (TypeError, ValueError) as exc:
        raise PersistedAssetContextInvariantError(
            "Current finding projection contains invalid decision evidence."
        ) from exc

    hydrated: list[NormalizedOccurrence] = []
    for occurrence, dedup_key in zip(occurrences, dedup_keys, strict=True):
        context = contexts_by_key.get(dedup_key)
        candidate = occurrence
        canonical_asset_id: str | None = None
        if context is not None:
            current_evidence = current_evidence_by_finding.get(context.finding.id)
            canonical_asset_id = _canonical_asset_id_from_current_projection(
                context,
                current_evidence=current_evidence,
            )
            candidate = _occurrence_with_persisted_asset_context(
                occurrence,
                context=context,
                canonical_asset_id=canonical_asset_id,
            )
        explicit_identity = (
            _asset_persistence_key(occurrence) if occurrence.asset_id is not None else None
        )
        explicit_asset = (
            explicit_assets_by_identity.get(explicit_identity)
            if explicit_identity is not None
            else None
        )
        if explicit_asset is not None:
            incoming_asset_id = normalize_asset_identity_value(occurrence.asset_id or "")
            if (
                context is not None
                and context.asset is not None
                and canonical_asset_id == incoming_asset_id
                and context.asset.id != explicit_asset.id
            ):
                raise PersistedAssetContextInvariantError(
                    "Current finding and explicit asset identity resolve to different assets."
                )
            candidate = _occurrence_with_persisted_asset_values(
                candidate,
                asset=explicit_asset,
                canonical_asset_id=incoming_asset_id,
                persisted_finding_id=(
                    context.finding.id
                    if context is not None
                    and context.asset is not None
                    and context.asset.id == explicit_asset.id
                    else None
                ),
            )
        hydrated.append(candidate)
    return hydrated


def _existing_assets_by_explicit_import_identity(
    occurrences: list[NormalizedOccurrence],
    *,
    session: Session,
    project_id: uuid.UUID,
) -> dict[str, Asset]:
    """Resolve only explicit asset IDs whose persisted identity is evidence-consistent."""
    occurrences_by_identity: dict[str, list[NormalizedOccurrence]] = {}
    preferred_key_by_identity: dict[str, str] = {}
    for occurrence in occurrences:
        if occurrence.asset_id is None:
            continue
        asset_id = normalize_asset_identity_value(occurrence.asset_id)
        if not asset_id or is_reserved_asset_storage_key(asset_id):
            continue
        identity_key = _asset_persistence_key(occurrence)
        if identity_key is None:  # pragma: no cover - explicit IDs always produce an identity
            continue
        occurrences_by_identity.setdefault(identity_key, []).append(occurrence)
        preferred_key_by_identity[identity_key] = asset_id
    if not occurrences_by_identity:
        return {}

    assets_by_key = _existing_assets_by_key(
        session=session,
        project_id=project_id,
        asset_keys=[
            *occurrences_by_identity,
            *preferred_key_by_identity.values(),
        ],
    )
    repository = AssetRepository(session)
    resolved: dict[str, Asset] = {}
    for identity_key, identity_occurrences in occurrences_by_identity.items():
        asset = assets_by_key.get(identity_key) or assets_by_key.get(
            preferred_key_by_identity[identity_key]
        )
        if asset is None:
            continue
        if all(
            repository.asset_matches_import_identity(
                asset,
                asset_id=occurrence.asset_id,
                target_kind=occurrence.target_kind,
                target_ref=occurrence.target_ref,
            )
            for occurrence in identity_occurrences
        ):
            resolved[identity_key] = asset
    return resolved


def _legacy_asset_contexts_by_current_dedup_key(
    occurrences: list[NormalizedOccurrence],
    *,
    dedup_parts: list[dict[str, str | None]],
    dedup_keys: list[str],
    exact_contexts_by_key: dict[str, PersistedFindingAssetContext],
    session: Session,
    project_id: uuid.UUID,
) -> dict[str, PersistedFindingAssetContext]:
    """Resolve evidence-proven legacy aliases before analysis and VEX matching."""
    unmatched = [
        (occurrence, parts, dedup_key)
        for occurrence, parts, dedup_key in zip(
            occurrences,
            dedup_parts,
            dedup_keys,
            strict=True,
        )
        if dedup_key not in exact_contexts_by_key
    ]
    if not unmatched:
        return {}

    vulnerabilities_by_cve = _existing_vulnerabilities_by_cve(
        session=session,
        cves=[occurrence.cve_id for occurrence, _, _ in unmatched],
    )
    component_storage_keys = [
        component_storage_key(component_identity)
        for _, parts, _ in unmatched
        if (component_identity := parts["component_identity"]) is not None
    ]
    components_by_key = _existing_components_by_identity_key(
        session=session,
        identity_keys=component_storage_keys,
    )
    lookup = _legacy_finding_identity_lookup(
        session=session,
        project_id=project_id,
        cves=[occurrence.cve_id for occurrence, _, _ in unmatched],
    )

    candidates_by_current_key: dict[str, Any] = {}
    for occurrence, parts, dedup_key in unmatched:
        vulnerability = vulnerabilities_by_cve.get(occurrence.cve_id)
        if vulnerability is None:
            continue
        component_identity = parts["component_identity"]
        component = (
            components_by_key.get(component_storage_key(component_identity))
            if component_identity is not None
            else None
        )
        if component_identity is not None and component is None:
            continue
        if component is not None and component.identity_material != component_identity:
            raise PersistedAssetContextInvariantError(
                "Canonical component identity resolved to contradictory persisted material."
            )
        legacy_target_ref = occurrence.target_ref or occurrence.asset_id
        identity: LegacyFindingIdentity = (
            vulnerability.id,
            component.id if component is not None else None,
            normalize_asset_target_kind(occurrence.target_kind),
            (
                normalize_asset_identity_value(legacy_target_ref)
                if legacy_target_ref is not None
                else None
            ),
        )
        base_identity = identity[:2]
        if identity in lookup.ambiguous_identities or base_identity in lookup.ambiguous_bases:
            raise PersistedAssetContextInvariantError(
                "Legacy finding scope evidence is ambiguous for the current import scope."
            )
        candidate = lookup.matches.get(identity)
        if candidate is not None:
            candidates_by_current_key[dedup_key] = candidate

    if not candidates_by_current_key:
        return {}
    contexts_by_legacy_key = _existing_finding_asset_context_by_dedup_key(
        session=session,
        project_id=project_id,
        dedup_keys=[candidate.dedup_key for candidate in candidates_by_current_key.values()],
    )
    return {
        current_key: context
        for current_key, candidate in candidates_by_current_key.items()
        if (context := contexts_by_legacy_key.get(candidate.dedup_key)) is not None
    }


def _canonical_asset_id_from_current_projection(
    context: PersistedFindingAssetContext,
    *,
    current_evidence: FindingDecisionEvidenceV2 | None,
) -> str | None:
    """Return only an explicit, identity-consistent asset id from current evidence."""
    if current_evidence is None:
        return None
    finding = context.finding
    if (
        current_evidence.finding_id != str(finding.id)
        or current_evidence.project_id != str(finding.project_id)
        or current_evidence.dedup_key != finding.dedup_key
    ):
        return None
    scope_asset_id = current_evidence.occurrence_scope.asset_id
    normalized = (
        normalize_asset_identity_value(scope_asset_id) if isinstance(scope_asset_id, str) else ""
    )
    if not normalized:
        legacy_asset_ids: set[str] = set()
        for occurrence in current_evidence.occurrences:
            value = occurrence.asset_id or occurrence.import_evidence.get("asset_id")
            if isinstance(value, str) and (candidate := normalize_asset_identity_value(value)):
                legacy_asset_ids.add(candidate)
        if len(legacy_asset_ids) != 1:
            return None
        normalized = next(iter(legacy_asset_ids))
    if context.asset is None:
        return None
    versioned_key = _asset_persistence_key(
        NormalizedOccurrence(
            cve_id=current_evidence.cve_id,
            target_kind=current_evidence.occurrence_scope.target_kind or "generic",
            target_ref=current_evidence.occurrence_scope.target_ref,
            asset_id=normalized,
        )
    )
    asset_key = context.asset.asset_key
    if is_legacy_reserved_asset_storage_key(asset_key):
        identity_matches = asset_key == legacy_reserved_asset_storage_key(normalized)
    elif is_versioned_asset_identity_key(asset_key):
        identity_matches = asset_key == versioned_key
    else:
        identity_matches = normalize_asset_identity_value(asset_key) == normalized
    if not identity_matches:
        # Asset keys are mutable through the Asset API. A manually renamed
        # linked row invalidates the old projected explicit ID; reusing it
        # could rebind this finding to an unrelated row that later claims the
        # released key.
        return None
    return normalized


def _occurrence_with_persisted_asset_context(
    occurrence: NormalizedOccurrence,
    *,
    context: PersistedFindingAssetContext,
    canonical_asset_id: str | None,
) -> NormalizedOccurrence:
    incoming_asset_id = _persisted_text(occurrence.asset_id)
    if incoming_asset_id is not None:
        incoming_asset_id = normalize_asset_identity_value(incoming_asset_id)
    if incoming_asset_id is not None and incoming_asset_id != canonical_asset_id:
        # A current upload/sidecar can deliberately remap this stable source
        # scope. Context from the previously linked asset must not bleed into
        # the newly named asset when the sidecar supplies only a partial row.
        return occurrence

    return _occurrence_with_persisted_asset_values(
        occurrence,
        asset=context.asset,
        canonical_asset_id=canonical_asset_id,
        persisted_finding_id=context.finding.id,
    )


def _occurrence_with_persisted_asset_values(
    occurrence: NormalizedOccurrence,
    *,
    asset: Asset | None,
    canonical_asset_id: str | None,
    persisted_finding_id: uuid.UUID | None,
) -> NormalizedOccurrence:
    """Hydrate absent decision inputs from one safely resolved relational asset."""
    evidence = dict(occurrence.raw_evidence)
    hydrated_fields: list[str] = []
    asset_id = occurrence.asset_id
    if asset_id is None and canonical_asset_id is not None:
        asset_id = canonical_asset_id
        evidence["asset_id"] = canonical_asset_id
        hydrated_fields.append("asset_id")

    if asset is not None:
        _inherit_persisted_text(
            evidence,
            aliases=("asset_owner", "owner"),
            value=_persisted_text(asset.owner),
            hydrated_field="owner",
            hydrated_fields=hydrated_fields,
        )
        _inherit_persisted_text(
            evidence,
            aliases=("asset_business_service", "business_service"),
            value=_persisted_text(asset.business_service),
            hydrated_field="business_service",
            hydrated_fields=hydrated_fields,
        )
        _inherit_persisted_text(
            evidence,
            aliases=("asset_environment", "environment"),
            value=_persisted_known_asset_value(asset.environment),
            hydrated_field="environment",
            hydrated_fields=hydrated_fields,
        )
        _inherit_persisted_text(
            evidence,
            aliases=("asset_exposure", "exposure"),
            value=_persisted_known_asset_value(asset.exposure),
            hydrated_field="exposure",
            hydrated_fields=hydrated_fields,
        )
        _inherit_persisted_text(
            evidence,
            aliases=("asset_criticality", "criticality"),
            value=_persisted_known_asset_value(asset.criticality),
            hydrated_field="criticality",
            hydrated_fields=hydrated_fields,
        )

    if not hydrated_fields and asset is None:
        return occurrence
    evidence.update(
        {
            "asset_context_source": _PERSISTED_ASSET_CONTEXT_SOURCE,
            "asset_context_hydrated_fields": hydrated_fields,
        }
    )
    if persisted_finding_id is not None:
        evidence["asset_context_persisted_finding_id"] = str(persisted_finding_id)
    if asset is not None and persisted_finding_id is None:
        evidence["asset_context_persisted_asset_row_id"] = str(asset.id)
    return NormalizedOccurrence(
        cve_id=occurrence.cve_id,
        component_name=occurrence.component_name,
        component_version=occurrence.component_version,
        target_kind=occurrence.target_kind,
        target_ref=occurrence.target_ref,
        asset_id=asset_id,
        source=occurrence.source,
        fix_version=occurrence.fix_version,
        raw_evidence=evidence,
    )


def _inherit_persisted_text(
    evidence: dict[str, Any],
    *,
    aliases: tuple[str, str],
    value: str | None,
    hydrated_field: str,
    hydrated_fields: list[str],
) -> None:
    """Fill both canonical aliases only when the current occurrence has no value."""
    if value is None or any(_non_blank_text(evidence.get(key)) for key in aliases):
        return
    for key in aliases:
        evidence[key] = value
    hydrated_fields.append(hydrated_field)


def _non_blank_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _persisted_text(value: object) -> str | None:
    raw_value = getattr(value, "value", value)
    if not isinstance(raw_value, str):
        return None
    normalized = raw_value.strip()
    return normalized or None


def _persisted_known_asset_value(value: object) -> str | None:
    """Return persisted classification evidence only when it is informative."""
    normalized = _persisted_text(value)
    return None if normalized == "unknown" else normalized


def _apply_workbench_vex(
    occurrences: list[NormalizedOccurrence],
    *,
    vex_path: Path,
) -> tuple[list[NormalizedOccurrence], dict[str, Any]]:
    statements, load_diagnostics = load_vex_files(
        [vex_path],
        return_diagnostics=True,
    )
    input_occurrences = [
        _input_occurrence_from_workbench_occurrence(occurrence) for occurrence in occurrences
    ]
    enriched_occurrences, match_diagnostics = apply_vex_statements(
        input_occurrences,
        statements,
        return_diagnostics=True,
    )
    return (
        [
            _workbench_occurrence_with_vex(original, enriched)
            for original, enriched in zip(occurrences, enriched_occurrences, strict=True)
        ],
        {
            "file_count": load_diagnostics.file_count,
            "statement_count": load_diagnostics.statement_count,
            "skipped_statements": load_diagnostics.skipped_statements,
            "matched_occurrences": match_diagnostics.matched_occurrences,
            "unmatched_occurrences": match_diagnostics.unmatched_occurrences,
            "ambiguous_occurrences": match_diagnostics.ambiguous_occurrences,
            "conflict_occurrences": match_diagnostics.conflict_occurrences,
            "warnings": [
                *load_diagnostics.warnings,
                *match_diagnostics.warnings,
            ],
        },
    )


def _parsed_input_from_workbench_occurrences(
    occurrences: list[NormalizedOccurrence],
    *,
    input_path: Path,
    input_type: str,
    base_parsed_input: ParsedInput | None = None,
    asset_context_summary: dict[str, Any] | None,
    vex_summary: dict[str, Any] | None,
) -> ParsedInput:
    input_occurrences = [
        _input_occurrence_from_workbench_occurrence(occurrence) for occurrence in occurrences
    ]
    warnings = [
        *(base_parsed_input.warnings if base_parsed_input is not None else []),
        *_summary_warnings(asset_context_summary),
        *_summary_warnings(vex_summary),
    ]
    total_rows = (
        base_parsed_input.total_rows if base_parsed_input is not None else len(input_occurrences)
    )
    warning_count = (
        len(base_parsed_input.warnings) if base_parsed_input is not None else len(warnings)
    )
    return finalize_occurrences(
        input_occurrences,
        input_format=base_parsed_input.input_format
        if base_parsed_input is not None
        else input_type,
        warnings=warnings,
        total_rows=total_rows,
        max_cves=None,
        input_paths=[str(input_path)],
        source_summaries=[
            InputSourceSummary(
                input_path=str(input_path),
                input_format=input_type,
                total_rows=total_rows,
                occurrence_count=len(input_occurrences),
                unique_cves=len({occurrence.cve_id for occurrence in input_occurrences}),
                warning_count=warning_count,
            )
        ],
        asset_match_conflict_count=int(
            (asset_context_summary or {}).get("ambiguous_occurrences") or 0
        ),
        vex_conflict_count=int((vex_summary or {}).get("conflict_occurrences") or 0),
    )


def _parse_errors(
    exc: Exception,
    *,
    filename: str,
    input_type: str,
) -> list[dict[str, Any]]:
    message = _sanitize_parser_error_message(str(exc))
    row_prefix = "generic-occurrence-csv row errors: "
    messages = (
        [item.strip() for item in message.removeprefix(row_prefix).split(";") if item.strip()]
        if message.startswith(row_prefix)
        else [message]
    )
    return [
        _parse_error_payload(
            item,
            filename=filename,
            input_type=input_type,
            error_type=exc.__class__.__name__,
        )
        for item in messages
    ]


def _parse_error_payload(
    message: str,
    *,
    filename: str,
    input_type: str,
    error_type: str,
) -> dict[str, Any]:
    return {
        "input_type": input_type,
        "filename": filename,
        "message": message,
        "error_type": error_type,
        "line": _parse_error_line(message),
        "field": _parse_error_field(message),
        "value": _parse_error_value(message),
    }


def _parse_error_line(message: str) -> int | None:
    match = re.search(r"\bline (?P<line>\d+)\b", message)
    return int(match.group("line")) if match else None


def _parse_error_field(message: str) -> str | None:
    lower_message = message.lower()
    return (
        "cve_id"
        if any(marker in lower_message for marker in ("cve_id column", "cve identifier"))
        else None
    )


def _parse_error_value(message: str) -> str | None:
    match = re.search(r"(?P<quote>['\"])(?P<value>.+?)(?P=quote)", message)
    return match.group("value") if match else None
