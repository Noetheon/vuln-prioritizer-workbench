"""Persistence orchestration facade for Workbench imports."""

from __future__ import annotations

# ruff: noqa: F401
import uuid
from dataclasses import replace
from typing import Any

from sqlmodel import Session, col, select

from app.decision_core.builders import (
    build_finding_decision_evidence,
    build_occurrence_evidence,
)
from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.identity import (
    FINDING_SCOPE_KEY_VERSION,
    OBSERVATION_KEY_VERSION,
)
from app.domain.asset_identity import is_reserved_asset_storage_key
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence
from app.models import Asset, Component
from app.repositories import AssetRepository, FindingRepository, RunRepository
from app.repositories.assets import AssetIdentityInvariantError
from app.repositories.findings import (
    ComponentPersistenceIdentity,
    normalize_component_persistence_identity,
)
from app.services.analysis import WorkbenchAnalysisResult
from app.services.import_execution_dedup import (
    _asset_persistence_key,
    _asset_storage_keys_by_identity,
    _dedup_key_parts,
    _finding_dedup_key,
    _legacy_asset_persistence_keys,
    _observation_key,
    _persistence_order_key,
    _preferred_asset_storage_key,
)
from app.services.import_execution_persistence_attack import (
    _attack_context_defensive_note,
    _attack_context_enabled,
    _attack_context_review_status,
    _persist_workbench_finding_attack_context,
    _technique_ids_from_context,
    _valid_attack_tactic_ids,
)
from app.services.import_execution_persistence_bulk import (
    _persist_workbench_occurrences_bulk_insert,
)
from app.services.import_execution_persistence_common import DEDUP_DECISION_SAMPLE_LIMIT
from app.services.import_execution_persistence_payloads import (
    _analysis_evidence_for_occurrence,
    _analysis_semantics_summary,
    _asset_projection_payload,
    _canonical_vulnerability_source_id,
    _decision_cvss_vector,
    _decision_cwe,
    _decision_data_quality_json,
    _decision_for_occurrence,
    _decision_modified,
    _decision_payload_for_occurrence,
    _decision_priority,
    _decision_provider_json,
    _decision_published,
    _finding_status_for_occurrence,
    _jsonable_model,
    _priority_state_for_occurrence,
    _scope_projection_payload,
    _scoped_operational_score_for_occurrence,
    _suppressed_by_vex_for_occurrence,
)
from app.services.import_execution_persistence_queries import (
    _chunks,
    _chunks_any,
    _existing_assets_by_key,
    _existing_components_by_identity_key,
    _existing_finding_asset_context_by_dedup_key,
    _existing_legacy_findings_by_identity,
    _existing_vulnerabilities_by_cve,
)

__all__ = [
    "DEDUP_DECISION_SAMPLE_LIMIT",
    "_analysis_evidence_for_occurrence",
    "_analysis_semantics_summary",
    "_attack_context_defensive_note",
    "_attack_context_review_status",
    "_chunks",
    "_chunks_any",
    "_decision_payload_for_occurrence",
    "_finding_status_for_occurrence",
    "_jsonable_model",
    "_persist_workbench_occurrences",
    "_priority_state_for_occurrence",
    "_suppressed_by_vex_for_occurrence",
    "_technique_ids_from_context",
    "_valid_attack_tactic_ids",
]


def _resolve_import_asset(
    *,
    asset_repo: AssetRepository,
    project_id: uuid.UUID,
    occurrence: NormalizedOccurrence,
    asset_identity_key: str,
    asset_key: str,
    asset_projection: dict[str, Any] | None,
    existing_finding: Any,
    linked_asset: Any,
    assets_by_key: dict[str, Any],
    persisted_assets_by_storage_key: dict[str, Any],
) -> Any:
    """Resolve a mutable asset link without changing stable source-target identity."""
    if asset_projection is None:
        raise ValueError("An import asset requires an aggregate projection.")

    asset: Any = None
    if occurrence.asset_id is None and linked_asset is not None:
        # A raw-only re-import must retain a canonical link established by an
        # earlier sidecar and must not downgrade known context to unknown.
        asset = asset_repo.apply_import_projection(
            linked_asset,
            asset_key=linked_asset.asset_key,
            name=linked_asset.name,
            target_ref=asset_projection["target_ref"] or linked_asset.target_ref,
            owner=asset_projection["owner"] or linked_asset.owner,
            business_service=(
                asset_projection["business_service"] or linked_asset.business_service
            ),
            environment=_known_projection_value(
                asset_projection["environment"],
                fallback=linked_asset.environment,
            ),
            exposure=_known_projection_value(
                asset_projection["exposure"],
                fallback=linked_asset.exposure,
            ),
            criticality=_known_projection_value(
                asset_projection["criticality"],
                fallback=linked_asset.criticality,
            ),
            flush=False,
        )
        assets_by_key[asset_identity_key] = asset
        return asset

    asset = assets_by_key.get(asset_identity_key)
    resolved_from_cache = asset is not None
    resolved_from_identity_key = False
    if not resolved_from_cache:
        # Once a real collision assigned the logical identity key, keep using
        # that row even if the formerly occupied readable key becomes free.
        # Explicit IDs are the exception: they canonically own their readable
        # key and a preflight below has already displaced a proven implicit
        # holder when necessary.
        asset = persisted_assets_by_storage_key.get(asset_identity_key)
        if asset is not None:
            readable_holder = persisted_assets_by_storage_key.get(asset_key)
            if occurrence.asset_id is None or (
                readable_holder is not None and readable_holder.id != asset.id
            ):
                asset_key = asset_identity_key
            resolved_from_identity_key = True
        else:
            asset = persisted_assets_by_storage_key.get(asset_key)
    if (
        asset is not None
        and not resolved_from_cache
        and not asset_repo.asset_matches_import_identity(
            asset,
            asset_id=occurrence.asset_id,
            target_kind=occurrence.target_kind,
            target_ref=occurrence.target_ref,
        )
    ):
        if resolved_from_identity_key:
            raise AssetIdentityInvariantError(
                "Persisted asset evidence contradicts its versioned identity key."
            )
        # A readable legacy key is already owned by a different logical
        # identity. The versioned identity is a deterministic collision key.
        asset_key = asset_identity_key
        asset = persisted_assets_by_storage_key.get(asset_key)
        if asset is not None and not asset_repo.asset_matches_import_identity(
            asset,
            asset_id=occurrence.asset_id,
            target_kind=occurrence.target_kind,
            target_ref=occurrence.target_ref,
        ):
            raise AssetIdentityInvariantError(
                "Persisted asset evidence contradicts its versioned identity key."
            )
    if asset is None and occurrence.target_ref is not None:
        # Pre-v2 targets used untagged keys. Promote such a
        # row only when every linked occurrence proves the same target scope.
        for legacy_asset_key in _legacy_asset_persistence_keys(occurrence):
            asset = asset_repo.get_evidence_proven_legacy_asset(
                project_id=project_id,
                legacy_asset_key=legacy_asset_key,
                asset_id=occurrence.asset_id,
                target_kind=occurrence.target_kind,
                target_ref=occurrence.target_ref,
            )
            if asset is not None:
                break
    if (
        asset is None
        and occurrence.asset_id is not None
        and existing_finding is not None
        and linked_asset is not None
        and asset_repo.asset_is_exclusively_linked_to_finding(
            asset_id=linked_asset.id,
            finding_id=existing_finding.id,
        )
        and asset_repo.asset_matches_import_identity(
            linked_asset,
            asset_id=occurrence.asset_id,
            target_kind=occurrence.target_kind,
            target_ref=occurrence.target_ref,
        )
    ):
        # Promote only an exclusively linked, evidence-proven provisional
        # raw-target asset in place. A shared or explicitly identified asset
        # must not be renamed when a sidecar changes just this finding scope.
        asset = linked_asset
    if asset is None:
        if occurrence.asset_id is not None and is_reserved_asset_storage_key(occurrence.asset_id):
            raise ValueError("Asset ID uses the reserved Workbench identity namespace.")
        asset = asset_repo.upsert_asset(
            project_id=project_id,
            asset_key=asset_key,
            name=occurrence.asset_id or occurrence.target_ref or asset_key,
            target_ref=asset_projection["target_ref"],
            owner=asset_projection["owner"],
            business_service=asset_projection["business_service"],
            environment=asset_projection["environment"],
            exposure=asset_projection["exposure"],
            criticality=asset_projection["criticality"],
            flush=False,
        )
    else:
        asset = asset_repo.apply_import_projection(
            asset,
            asset_key=asset_key,
            name=occurrence.asset_id or asset.name,
            target_ref=asset_projection["target_ref"] or asset.target_ref,
            owner=asset_projection["owner"] or asset.owner,
            business_service=asset_projection["business_service"] or asset.business_service,
            environment=_known_projection_value(
                asset_projection["environment"],
                fallback=asset.environment,
            ),
            exposure=_known_projection_value(
                asset_projection["exposure"],
                fallback=asset.exposure,
            ),
            criticality=_known_projection_value(
                asset_projection["criticality"],
                fallback=asset.criticality,
            ),
            flush=False,
        )
    assets_by_key[asset_identity_key] = asset
    persisted_assets_by_storage_key[asset.asset_key] = asset
    return asset


def _relocate_implicit_asset_for_explicit_identity(
    *,
    asset_repo: AssetRepository,
    project_id: uuid.UUID,
    explicit_occurrence: NormalizedOccurrence,
    explicit_identity_key: str,
    explicit_storage_key: str,
    assets_by_key: dict[str, Any],
    persisted_assets_by_storage_key: dict[str, Any],
) -> None:
    """
    Give a readable key to its explicit ID independent of import order.

    A persisted row is moved only when its complete occurrence history proves
    one purely implicit source-target identity and its current key is that
    identity's canonical readable key.  Ambiguous or manually named state is
    rejected instead of silently inverting asset-key semantics.
    """
    if explicit_occurrence.asset_id is None:
        return
    readable_holder = persisted_assets_by_storage_key.get(explicit_storage_key)
    if readable_holder is None:
        return
    if asset_repo.asset_matches_import_identity(
        readable_holder,
        asset_id=explicit_occurrence.asset_id,
        target_kind=explicit_occurrence.target_kind,
        target_ref=explicit_occurrence.target_ref,
    ):
        # Reuse the evidence validation in the row loop.  Large explicit-ID
        # reimports must not pay for the same history queries twice.
        assets_by_key[explicit_identity_key] = readable_holder
        return

    implicit_scope = asset_repo.evidence_proven_implicit_import_identity(readable_holder)
    if implicit_scope is None:
        return
    implicit_kind, implicit_ref = implicit_scope
    implicit_occurrence = NormalizedOccurrence(
        cve_id=explicit_occurrence.cve_id,
        target_kind=implicit_kind,
        target_ref=implicit_ref,
    )
    implicit_identity_key = _asset_persistence_key(implicit_occurrence)
    implicit_preferred_key = _preferred_asset_storage_key(
        implicit_occurrence,
        allow_legacy_reserved=True,
    )
    if implicit_identity_key is None or implicit_preferred_key != readable_holder.asset_key:
        return
    identity_holder = persisted_assets_by_storage_key.get(implicit_identity_key)
    if identity_holder is None:
        identity_holder = asset_repo.get_project_asset_by_key(project_id, implicit_identity_key)
    if identity_holder is not None and identity_holder.id != readable_holder.id:
        raise AssetIdentityInvariantError(
            "The displaced implicit asset identity key is already owned by another asset."
        )

    previous_storage_key = readable_holder.asset_key
    asset_repo.apply_import_projection(
        readable_holder,
        asset_key=implicit_identity_key,
        name=readable_holder.name,
        target_ref=readable_holder.target_ref,
        owner=readable_holder.owner,
        business_service=readable_holder.business_service,
        environment=readable_holder.environment,
        exposure=readable_holder.exposure,
        criticality=readable_holder.criticality,
        # Free the unique readable key before a persisted explicit fallback is
        # promoted or a new explicit row is inserted later in this transaction.
        flush=True,
    )
    if persisted_assets_by_storage_key.get(previous_storage_key) is readable_holder:
        persisted_assets_by_storage_key.pop(previous_storage_key)
    persisted_assets_by_storage_key[implicit_identity_key] = readable_holder
    assets_by_key[implicit_identity_key] = readable_holder

    # A previously persisted explicit identity may already occupy its versioned
    # fallback from the old order-dependent behavior.  Resolution will promote
    # that same row to the now-free readable key; never conflate it with the
    # displaced implicit asset.
    explicit_holder = persisted_assets_by_storage_key.get(explicit_identity_key)
    if explicit_holder is readable_holder:
        raise AssetIdentityInvariantError(
            "One asset row cannot prove both explicit and implicit identities."
        )


def _known_projection_value(value: Any, *, fallback: Any) -> Any:
    return fallback if value in {None, "", "unknown"} else value


def _existing_import_assets_by_id(
    *,
    session: Session,
    asset_ids: list[uuid.UUID],
) -> dict[uuid.UUID, Asset]:
    """Batch-load relational asset links needed by legacy re-imports."""
    assets: dict[uuid.UUID, Asset] = {}
    unique_ids = list(dict.fromkeys(asset_ids))
    for index in range(0, len(unique_ids), 500):
        statement = select(Asset).where(col(Asset.id).in_(unique_ids[index : index + 500]))
        for asset in session.exec(statement).all():
            assets[asset.id] = asset
    return assets


def _persist_workbench_occurrences(
    *,
    session: Session,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    occurrences: list[NormalizedOccurrence],
    analysis_result: WorkbenchAnalysisResult,
    analysis_evidence_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    bulk_summary = _persist_workbench_occurrences_bulk_insert(
        session=session,
        project_id=project_id,
        run_id=run_id,
        occurrences=occurrences,
        analysis_result=analysis_result,
        analysis_evidence_id=analysis_evidence_id,
    )
    if bulk_summary is not None:
        return bulk_summary

    asset_repo = AssetRepository(session)
    finding_repo = FindingRepository(session)
    run_repo = RunRepository(session)
    decisions: list[dict[str, Any]] = []
    finding_evidence_by_id: dict[uuid.UUID, FindingDecisionEvidenceV2] = {}
    created_finding_ids: set[uuid.UUID] = set()
    updated_finding_ids: set[uuid.UUID] = set()
    touched_finding_ids: set[str] = set()
    attack_context_finding_ids: set[uuid.UUID] = set()
    dedup_keys = [
        _finding_dedup_key(_dedup_key_parts(project_id, occurrence)) for occurrence in occurrences
    ]
    persisted_contexts_by_dedup_key = _existing_finding_asset_context_by_dedup_key(
        session=session,
        project_id=project_id,
        dedup_keys=dedup_keys,
    )
    findings_by_dedup_key = {
        dedup_key: context.finding for dedup_key, context in persisted_contexts_by_dedup_key.items()
    }
    legacy_findings_by_identity = _existing_legacy_findings_by_identity(
        session=session,
        project_id=project_id,
        cves=[occurrence.cve_id for occurrence in occurrences],
    )
    occurrences_by_dedup_key: dict[str, list[NormalizedOccurrence]] = {}
    occurrences_by_cve: dict[str, list[NormalizedOccurrence]] = {}
    component_occurrences_by_key: dict[str, list[NormalizedOccurrence]] = {}
    for occurrence, dedup_key in zip(occurrences, dedup_keys, strict=True):
        occurrences_by_dedup_key.setdefault(dedup_key, []).append(occurrence)
        occurrences_by_cve.setdefault(occurrence.cve_id, []).append(occurrence)
        component_key = _dedup_key_parts(project_id, occurrence)["component_identity"]
        if component_key is not None:
            component_occurrences_by_key.setdefault(component_key, []).append(occurrence)
    canonical_asset_id_by_dedup_key: dict[str, str | None] = {}
    for scoped_occurrences in occurrences_by_dedup_key.values():
        explicit_asset_ids = {
            occurrence.asset_id
            for occurrence in scoped_occurrences
            if occurrence.asset_id is not None
        }
        if len(explicit_asset_ids) > 1:
            raise ValueError("One finding scope cannot resolve to multiple canonical asset IDs.")
        canonical_asset_id_by_dedup_key[
            _finding_dedup_key(_dedup_key_parts(project_id, scoped_occurrences[0]))
        ] = next(iter(explicit_asset_ids), None)
    relational_asset_occurrences = [
        (
            occurrence
            if occurrence.asset_id is not None or canonical_asset_id_by_dedup_key[dedup_key] is None
            else replace(
                occurrence,
                asset_id=canonical_asset_id_by_dedup_key[dedup_key],
            )
        )
        for occurrence, dedup_key in zip(occurrences, dedup_keys, strict=True)
    ]
    asset_occurrences_by_key: dict[str, list[NormalizedOccurrence]] = {}
    for occurrence in relational_asset_occurrences:
        asset_key = _asset_persistence_key(occurrence)
        if asset_key is not None:
            asset_occurrences_by_key.setdefault(asset_key, []).append(occurrence)
    scope_projection_by_dedup_key = {
        dedup_key: _scope_projection_payload(
            _decision_for_occurrence(analysis_result, scoped_occurrences[0]),
            scoped_occurrences,
        )
        for dedup_key, scoped_occurrences in occurrences_by_dedup_key.items()
    }
    component_projection_by_key = {
        component_key: _canonical_component_projection(component_occurrences)
        for component_key, component_occurrences in component_occurrences_by_key.items()
    }
    asset_projection_by_key = {
        asset_key: _asset_projection_payload(asset_occurrences)
        for asset_key, asset_occurrences in asset_occurrences_by_key.items()
    }
    asset_storage_key_by_identity = _asset_storage_keys_by_identity(
        asset_occurrences_by_key,
        allow_legacy_reserved=True,
    )
    vulnerability_occurrence_by_cve = {
        cve_id: min(
            cve_occurrences,
            key=lambda item: _persistence_order_key(project_id, item),
        )
        for cve_id, cve_occurrences in occurrences_by_cve.items()
    }
    vulnerability_source_id_by_cve = {
        cve_id: _canonical_vulnerability_source_id(cve_occurrences)
        for cve_id, cve_occurrences in occurrences_by_cve.items()
    }
    linked_assets_by_finding_id = {
        context.finding.id: context.asset
        for context in persisted_contexts_by_dedup_key.values()
        if context.asset is not None
    }
    legacy_assets_by_id = _existing_import_assets_by_id(
        session=session,
        asset_ids=[
            finding.asset_id
            for finding in legacy_findings_by_identity.values()
            if finding.asset_id is not None and finding.id not in linked_assets_by_finding_id
        ],
    )
    for finding in legacy_findings_by_identity.values():
        if finding.asset_id is not None and finding.asset_id in legacy_assets_by_id:
            linked_assets_by_finding_id[finding.id] = legacy_assets_by_id[finding.asset_id]

    persisted_assets_by_storage_key = _existing_assets_by_key(
        session=session,
        project_id=project_id,
        asset_keys=[
            *asset_storage_key_by_identity.keys(),
            *asset_storage_key_by_identity.values(),
        ],
    )
    assets_by_key: dict[str, Any] = {}
    for candidate_asset_identity_key in sorted(asset_occurrences_by_key):
        explicit_occurrences = [
            occurrence
            for occurrence in asset_occurrences_by_key[candidate_asset_identity_key]
            if occurrence.asset_id is not None
        ]
        if not explicit_occurrences:
            continue
        _relocate_implicit_asset_for_explicit_identity(
            asset_repo=asset_repo,
            project_id=project_id,
            explicit_occurrence=min(
                explicit_occurrences,
                key=lambda item: _persistence_order_key(project_id, item),
            ),
            explicit_identity_key=candidate_asset_identity_key,
            explicit_storage_key=asset_storage_key_by_identity[candidate_asset_identity_key],
            assets_by_key=assets_by_key,
            persisted_assets_by_storage_key=persisted_assets_by_storage_key,
        )
    persisted_components_by_storage_key = _existing_components_by_identity_key(
        session=session,
        identity_keys=[identity.storage_key for identity in component_projection_by_key.values()],
    )
    vulnerabilities_by_cve = _existing_vulnerabilities_by_cve(
        session=session,
        cves=list(vulnerability_occurrence_by_cve),
    )
    components_by_key: dict[str, Component] = {}
    for projected_component_identity in component_projection_by_key.values():
        prepared_component = finding_repo.upsert_component(
            name=projected_component_identity.name,
            version=projected_component_identity.version,
            purl=projected_component_identity.purl,
            ecosystem=projected_component_identity.ecosystem,
            package_type=projected_component_identity.package_type,
            existing_component=persisted_components_by_storage_key.get(
                projected_component_identity.storage_key
            ),
            lookup_existing=False,
            flush=False,
        )
        persisted_components_by_storage_key[projected_component_identity.storage_key] = (
            prepared_component
        )
        components_by_key[projected_component_identity.scope_key] = prepared_component

    for cve_id, vulnerability_occurrence in vulnerability_occurrence_by_cve.items():
        vulnerability_decision = _decision_for_occurrence(
            analysis_result,
            vulnerability_occurrence,
        )
        vulnerability = finding_repo.upsert_vulnerability(
            cve_id=cve_id,
            source_id=vulnerability_source_id_by_cve[cve_id],
            title=cve_id,
            description=vulnerability_decision.description,
            cvss_score=vulnerability_decision.cvss_base_score,
            cvss_vector=_decision_cvss_vector(vulnerability_decision),
            severity=(
                vulnerability_decision.cvss_severity
                or _string_evidence(vulnerability_occurrence.raw_evidence, "severity")
            ),
            cwe=_decision_cwe(vulnerability_decision),
            published_at=_decision_published(vulnerability_decision),
            modified_at=_decision_modified(vulnerability_decision),
            provider_json=_decision_provider_json(vulnerability_decision),
            existing_vulnerability=vulnerabilities_by_cve.get(cve_id),
            lookup_existing=False,
            flush=False,
        )
        vulnerabilities_by_cve[cve_id] = vulnerability
    data_quality_by_cve: dict[str, dict[str, Any]] = {}
    with session.no_autoflush:
        for index, (occurrence, relational_asset_occurrence) in enumerate(
            zip(occurrences, relational_asset_occurrences, strict=True),
            start=1,
        ):
            dedup_parts = _dedup_key_parts(project_id, occurrence)
            dedup_key = _finding_dedup_key(dedup_parts)
            decision = _decision_for_occurrence(analysis_result, occurrence)
            occurrence_scope = scope_projection_by_dedup_key[dedup_key]
            scoped_score = _scoped_operational_score_for_occurrence(decision, occurrence)
            decision_payload = _decision_payload_for_occurrence(
                decision,
                occurrence,
                occurrence_scope=occurrence_scope,
                scoped_score=scoped_score,
            )
            data_quality_payload = data_quality_by_cve.get(occurrence.cve_id)
            if data_quality_payload is None:
                data_quality_payload = _decision_data_quality_json(decision)
                data_quality_by_cve[occurrence.cve_id] = data_quality_payload
            component = None
            component_scope_key = dedup_parts["component_identity"]
            component_identity = (
                component_projection_by_key.get(component_scope_key)
                if component_scope_key is not None
                else None
            )
            if component_identity is not None:
                component = components_by_key.get(component_identity.scope_key)
            vulnerability = vulnerabilities_by_cve[occurrence.cve_id]
            existing_finding = findings_by_dedup_key.get(dedup_key)
            resolved_from_legacy_scope = False
            if existing_finding is None:
                # Consume one evidence-proven legacy scope candidate at most once.
                legacy_target_ref = occurrence.target_ref or occurrence.asset_id
                existing_finding = legacy_findings_by_identity.pop(
                    (
                        vulnerability.id,
                        component.id if component else None,
                        occurrence.target_kind,
                        legacy_target_ref,
                    ),
                    None,
                )
                resolved_from_legacy_scope = existing_finding is not None
            asset_identity_key = _asset_persistence_key(relational_asset_occurrence)
            asset = (
                _resolve_import_asset(
                    asset_repo=asset_repo,
                    project_id=project_id,
                    occurrence=relational_asset_occurrence,
                    asset_identity_key=asset_identity_key,
                    asset_key=asset_storage_key_by_identity[asset_identity_key],
                    asset_projection=(
                        asset_projection_by_key[asset_identity_key]
                        if asset_identity_key is not None
                        else None
                    ),
                    existing_finding=existing_finding,
                    linked_asset=(
                        linked_assets_by_finding_id.get(existing_finding.id)
                        if existing_finding is not None
                        else None
                    ),
                    assets_by_key=assets_by_key,
                    persisted_assets_by_storage_key=persisted_assets_by_storage_key,
                )
                if asset_identity_key is not None
                else None
            )
            action = "reused" if existing_finding is not None else "created"
            observation_key = _observation_key(occurrence)
            evidence_payload = {
                "import": dict(occurrence.raw_evidence),
                "analysis": _analysis_evidence_for_occurrence(
                    analysis_result,
                    decision,
                    occurrence,
                    priority_state=decision_payload.get("priority_state"),
                    occurrence_scope=occurrence_scope,
                    operational_score=scoped_score[0],
                ),
                "dedup": {
                    "key": dedup_key,
                    "key_version": FINDING_SCOPE_KEY_VERSION,
                    "observation_key": observation_key,
                    "observation_key_version": OBSERVATION_KEY_VERSION,
                    "action": action,
                    "parts": dedup_parts,
                },
            }
            finding = finding_repo.create_or_update_finding(
                project_id=project_id,
                vulnerability_id=vulnerability.id,
                cve_id=occurrence.cve_id,
                dedup_key=dedup_key,
                component_id=component.id if component else None,
                asset_id=asset.id if asset else None,
                status=_finding_status_for_occurrence(decision, occurrence),
                existing_finding=existing_finding,
                lookup_existing=False,
                allow_asset_rebind=(
                    existing_finding is not None
                    and asset is not None
                    and (
                        relational_asset_occurrence.asset_id is not None
                        or resolved_from_legacy_scope
                    )
                    and existing_finding.asset_id != asset.id
                ),
                flush=False,
            )
            findings_by_dedup_key[dedup_key] = finding
            if action == "created":
                session.flush()
            if finding.id not in attack_context_finding_ids and _attack_context_enabled(
                analysis_result,
                decision,
            ):
                _persist_workbench_finding_attack_context(
                    session=session,
                    run_id=run_id,
                    finding_id=finding.id,
                    decision=decision,
                )
                attack_context_finding_ids.add(finding.id)
            if action == "created":
                created_finding_ids.add(finding.id)
            elif finding.id not in created_finding_ids:
                updated_finding_ids.add(finding.id)
            touched_finding_ids.add(str(finding.id))
            occurrence_row = run_repo.add_finding_occurrence(
                finding_id=finding.id,
                analysis_run_id=run_id,
                source=occurrence.source,
                raw_reference=_string_evidence(occurrence.raw_evidence, "source_record_id"),
                fix_version=occurrence.fix_version,
                evidence_json={
                    **dict(occurrence.raw_evidence),
                    "target_kind": occurrence.target_kind,
                    "target_ref": occurrence.target_ref,
                    "asset_id": occurrence.asset_id,
                    "dedup_key": dedup_key,
                    "dedup_action": action,
                    "observation_key": observation_key,
                    "observation_key_version": OBSERVATION_KEY_VERSION,
                },
                flush=False,
            )
            occurrence_evidence = build_occurrence_evidence(
                analysis_run_id=run_id,
                occurrence_id=occurrence_row.id,
                source=occurrence.source,
                scanner=None,
                raw_reference=_string_evidence(occurrence.raw_evidence, "source_record_id"),
                fix_version=occurrence.fix_version,
                raw_evidence={
                    **dict(occurrence.raw_evidence),
                    "component_name": occurrence.component_name,
                    "component_version": occurrence.component_version,
                    "target_kind": occurrence.target_kind,
                    "target_ref": occurrence.target_ref,
                    "asset_id": occurrence.asset_id,
                },
                dedup=evidence_payload["dedup"],
            )
            existing_evidence = finding_evidence_by_id.get(finding.id)
            if existing_evidence is None:
                finding_evidence_by_id[finding.id] = build_finding_decision_evidence(
                    project_id=project_id,
                    run_id=run_id,
                    finding_id=finding.id,
                    cve_id=occurrence.cve_id,
                    dedup_key=dedup_key,
                    status=finding.status.value,
                    priority=_decision_priority(decision).value,
                    priority_rank=decision.priority_rank,
                    risk_score=float(scoped_score[0]),
                    operational_rank=decision.operational_rank or index,
                    in_kev=decision.in_kev,
                    epss=decision.epss,
                    cvss_base_score=decision.cvss_base_score,
                    attack_mapped=decision.attack_mapped,
                    suppressed_by_vex=_suppressed_by_vex_for_occurrence(decision, occurrence),
                    under_investigation=decision.under_investigation,
                    waived=decision.waived,
                    rationale=decision.rationale,
                    recommended_action=decision.recommended_action,
                    decision_payload=decision_payload,
                    data_quality_payload=data_quality_payload,
                    provider_payload=_decision_provider_json(decision),
                    occurrence_scope=occurrence_scope,
                    occurrence_evidence=[occurrence_evidence],
                )
            else:
                existing_evidence.occurrences.append(occurrence_evidence)
            if len(decisions) < DEDUP_DECISION_SAMPLE_LIMIT:
                decisions.append(
                    {
                        "action": action,
                        "dedup_key": dedup_key,
                        "finding_id": str(finding.id),
                        "cve_id": occurrence.cve_id,
                        "source_id": dedup_parts["source_id"],
                        "component_identity": dedup_parts["component_identity"],
                        "target_kind": dedup_parts["target_kind"],
                        "target_ref": dedup_parts["target_ref"],
                    }
                )
    session.flush()
    created_count = len(created_finding_ids)
    updated_count = len(updated_finding_ids)

    return {
        "occurrence_count": len(occurrences),
        "finding_count": len(touched_finding_ids),
        "created_findings": created_count,
        "updated_findings": updated_count,
        "analysis_semantics": _analysis_semantics_summary(
            occurrences=occurrences,
            finding_count=len(touched_finding_ids),
            analysis_result=analysis_result,
        ),
        "dedup_summary": {
            "key_version": FINDING_SCOPE_KEY_VERSION,
            "created_findings": created_count,
            "updated_findings": updated_count,
            "reused_findings": updated_count,
            "decision_count": len(occurrences),
            "decisions": decisions,
            "decision_sample_limit": DEDUP_DECISION_SAMPLE_LIMIT,
            "omitted_decisions": max(0, len(occurrences) - len(decisions)),
        },
        "finding_evidence": list(finding_evidence_by_id.values()),
    }


def _canonical_component_package_type(
    *,
    occurrence_scope: dict[str, Any],
    occurrences: list[NormalizedOccurrence],
) -> str | None:
    """Project stable component package metadata for one already-grouped scope."""
    purl = _string_evidence(occurrence_scope, "purl")
    if purl:
        scheme, separator, remainder = purl.strip().casefold().partition(":")
        package_type, path_separator, _path = remainder.partition("/")
        if scheme == "pkg" and separator and path_separator and package_type:
            return package_type
    candidates = {
        value.strip().casefold()
        for occurrence in occurrences
        if (value := _string_evidence(occurrence.raw_evidence, "package_type")) and value.strip()
    }
    return min(candidates) if candidates else None


def _canonical_component_projection(
    occurrences: list[NormalizedOccurrence],
) -> ComponentPersistenceIdentity:
    """Project one shared component row independently of scope and upload ordering."""
    if not occurrences:
        raise ValueError("A component projection requires at least one occurrence.")
    identities = [
        normalize_component_persistence_identity(
            name=occurrence.component_name,
            version=occurrence.component_version,
            purl=_string_evidence(occurrence.raw_evidence, "purl"),
            ecosystem=_string_evidence(occurrence.raw_evidence, "package_type"),
            package_type=_string_evidence(occurrence.raw_evidence, "package_type"),
        )
        for occurrence in occurrences
    ]
    scope_keys = {identity.scope_key for identity in identities}
    if len(scope_keys) != 1:
        raise ValueError("One component projection cannot span multiple identities.")

    names = {identity.name for identity in identities}
    versions = {identity.version for identity in identities if identity.version is not None}
    purls = {identity.purl for identity in identities if identity.purl is not None}
    if len(purls) > 1:
        raise ValueError("One component identity cannot resolve to multiple canonical PURLs.")
    purl = next(iter(purls), None)
    package_type = _canonical_component_package_type(
        occurrence_scope={"purl": purl},
        occurrences=occurrences,
    )
    projected = normalize_component_persistence_identity(
        name=min(names, key=lambda value: (value.casefold(), value)),
        version=(min(versions, key=lambda value: (value.casefold(), value)) if versions else None),
        purl=purl,
        ecosystem=package_type,
        package_type=package_type,
    )
    if projected.scope_key != next(iter(scope_keys)):
        raise ValueError("Projected component metadata changed the component identity.")
    return projected
