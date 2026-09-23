"""Asset repository for Workbench persistence."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, func, select

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.evaluation import ScopeEvaluationInput
from app.domain.asset_context_projection import (
    _asset_criticality,
    _asset_environment,
    _asset_exposure,
    _asset_snapshot,
    _changed_asset_fields,
    _records_by_asset_key,
)
from app.domain.asset_identity import (
    is_reserved_asset_storage_key,
    normalize_asset_identity_value,
    normalize_asset_target_kind,
    validate_asset_key_update,
    validate_operator_asset_key,
)
from app.domain.engine.inputs.loader import AssetContextCatalog
from app.domain.engine.inputs.parsers.common import (
    normalize_asset_criticality,
    normalize_asset_environment,
    normalize_asset_exposure,
)
from app.models import (
    Asset,
    AssetCreate,
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
    AssetUpdate,
    Finding,
    FindingCurrentProjection,
    FindingOccurrence,
)
from app.models.base import get_datetime_utc
from app.models.occurrence_identity import (
    OCCURRENCE_IDENTITY_FIELDS,
    occurrence_identity_expressions,
)
from app.repositories.current_projections import FindingCurrentProjectionRepository

ASSET_CONTEXT_RESCORE_FLAG = "asset_context_rescore_needed"


class AssetIdentityInvariantError(RuntimeError):
    """Raised when persisted evidence contradicts a versioned asset identity."""


@dataclass(frozen=True, slots=True)
class AssetFindingSummary:
    """Bounded list-view state for one asset."""

    finding_count: int = 0
    rescore_needed: bool = False


@dataclass(frozen=True, slots=True)
class AssetIdentityEvidence:
    """One read-pass proof from distinct historical identity facts, never persisted."""

    asset_id: uuid.UUID
    has_findings: bool
    complete_history: bool
    explicit_ids: frozenset[str]
    target_scopes: frozenset[tuple[str, str]]
    invalid_asset_id: bool
    blank_asset_id: bool
    incomplete_scope: bool


class AssetRepository:
    """Asset persistence helpers."""

    def __init__(self, session: Session) -> None:
        """Initialize a new instance of AssetRepository."""
        self.session = session

    def upsert_asset(
        self,
        *,
        project_id: uuid.UUID,
        asset_key: str,
        name: str | None = None,
        target_ref: str | None = None,
        owner: str | None = None,
        business_service: str | None = None,
        environment: AssetEnvironment | str = AssetEnvironment.UNKNOWN,
        exposure: AssetExposure | str = AssetExposure.UNKNOWN,
        criticality: AssetCriticality | str = AssetCriticality.UNKNOWN,
        flush: bool = True,
    ) -> Asset:
        """Create or update a project-scoped asset by business dedup key."""
        asset_key = normalize_asset_identity_value(asset_key)
        if not asset_key:
            raise ValueError("Asset key must not be blank.")
        target_ref = normalize_asset_identity_value(target_ref) if target_ref is not None else None
        statement = select(Asset).where(
            Asset.project_id == project_id,
            Asset.asset_key == asset_key,
        )
        asset = self.session.exec(statement).first()
        if asset is None:
            asset = Asset(project_id=project_id, asset_key=asset_key, name=name or asset_key)
            self.session.add(asset)
        elif name is not None:
            asset.name = name

        asset.target_ref = target_ref
        asset.owner = owner
        asset.business_service = business_service
        asset.environment = AssetEnvironment(environment)
        asset.exposure = AssetExposure(exposure)
        asset.criticality = AssetCriticality(criticality)
        if flush:
            self.session.flush()
        return asset

    def create_asset(self, *, project_id: uuid.UUID, asset_in: AssetCreate) -> Asset:
        """Create or update a project asset from API payload."""
        asset_key = validate_operator_asset_key(asset_in.asset_key)
        return self.upsert_asset(
            project_id=project_id,
            asset_key=asset_key,
            name=asset_in.name,
            target_ref=asset_in.target_ref,
            owner=asset_in.owner,
            business_service=asset_in.business_service,
            environment=asset_in.environment,
            exposure=asset_in.exposure,
            criticality=asset_in.criticality,
        )

    def apply_import_projection(
        self,
        asset: Asset,
        *,
        asset_key: str,
        name: str,
        target_ref: str | None,
        owner: str | None,
        business_service: str | None,
        environment: AssetEnvironment | str,
        exposure: AssetExposure | str,
        criticality: AssetCriticality | str,
        flush: bool = True,
    ) -> Asset:
        """Apply an import projection, including an explicit provisional-key promotion."""
        normalized_asset_key = normalize_asset_identity_value(asset_key)
        if not normalized_asset_key:
            raise ValueError("Asset key must not be blank.")
        previous = _asset_snapshot(asset)
        asset.asset_key = normalized_asset_key
        asset.name = name
        asset.target_ref = (
            normalize_asset_identity_value(target_ref) if target_ref is not None else None
        )
        asset.owner = owner
        asset.business_service = business_service
        asset.environment = AssetEnvironment(environment)
        asset.exposure = AssetExposure(exposure)
        asset.criticality = AssetCriticality(criticality)
        asset.updated_at = get_datetime_utc()
        self.session.add(asset)
        changed_fields = _changed_asset_fields(previous, _asset_snapshot(asset))
        if changed_fields:
            # An import can update one finding while reusing an asset that is
            # shared by older findings.  Those older projections must not keep
            # presenting their pre-change score as current.  Evidence written
            # later in this import supersedes the flag for touched findings;
            # every untouched projection remains explicitly stale until the
            # normal asset recalculation workflow refreshes it.
            self.mark_asset_findings_rescore_needed(
                asset_id=asset.id,
                changed_fields=changed_fields,
                changed_at=asset.updated_at,
                flush=False,
            )
        if flush:
            self.session.flush()
        return asset

    def import_asset_context_catalog(
        self,
        *,
        project_id: uuid.UUID,
        catalog: AssetContextCatalog,
    ) -> dict[str, Any]:
        """Import asset-context records into editable project asset rows."""
        records = _records_by_asset_key([rule.asset_record for rule in catalog.rules])
        created_assets = 0
        updated_assets = 0
        unchanged_assets = 0
        rescore_needed_findings = 0
        asset_keys: list[str] = []

        # Validate the complete catalog before mutating any ORM state.  The API
        # transaction would roll a late failure back, but repository callers may
        # deliberately catch validation errors and continue using their session.
        for record in records:
            validate_operator_asset_key(record.asset_id)

        for record in records:
            existing = self.get_project_asset_by_key(project_id, record.asset_id)
            previous = _asset_snapshot(existing) if existing is not None else None
            asset = self.upsert_asset(
                project_id=project_id,
                asset_key=record.asset_id,
                name=record.asset_id,
                target_ref=record.target_ref,
                owner=record.owner,
                business_service=record.business_service,
                environment=_asset_environment(record.environment),
                exposure=_asset_exposure(record.exposure),
                criticality=_asset_criticality(record.criticality),
            )
            asset_keys.append(asset.asset_key)
            if previous is None:
                created_assets += 1
                continue

            changed_fields = _changed_asset_fields(previous, _asset_snapshot(asset))
            if changed_fields:
                updated_assets += 1
                rescore_needed_findings += self.mark_asset_findings_rescore_needed(
                    asset_id=asset.id,
                    changed_fields=changed_fields,
                )
            else:
                unchanged_assets += 1

        diagnostics = catalog.diagnostics
        return {
            "project_id": project_id,
            "imported_assets": len(records),
            "created_assets": created_assets,
            "updated_assets": updated_assets,
            "unchanged_assets": unchanged_assets,
            "rescore_needed_findings": rescore_needed_findings,
            "total_rows": diagnostics.total_rows,
            "loaded_rows": diagnostics.loaded_rows,
            "skipped_rows": diagnostics.skipped_rows,
            "warnings": list(diagnostics.warnings),
            "asset_keys": asset_keys,
        }

    def get_asset(self, asset_id: uuid.UUID) -> Asset | None:
        """Return an asset by primary key."""
        return self.session.get(Asset, asset_id)

    def get_project_asset_by_key(self, project_id: uuid.UUID, asset_key: str) -> Asset | None:
        """Return a project-scoped asset by business key."""
        normalized_asset_key = normalize_asset_identity_value(asset_key)
        statement = select(Asset).where(
            Asset.project_id == project_id,
            Asset.asset_key == normalized_asset_key,
        )
        return self.session.exec(statement).first()

    def get_evidence_proven_legacy_asset(
        self,
        *,
        project_id: uuid.UUID,
        legacy_asset_key: str,
        asset_id: str | None,
        target_kind: str,
        target_ref: str,
    ) -> Asset | None:
        """Return a legacy unnamespaced asset only when all occurrence evidence agrees."""
        asset = self.get_project_asset_by_key(project_id, legacy_asset_key)
        if asset is None:
            return None
        history = self.import_identity_evidence(asset.id)
        if not history.has_findings or not history.complete_history or history.invalid_asset_id:
            return None

        expected_scope = (
            normalize_asset_target_kind(target_kind),
            normalize_asset_identity_value(target_ref),
        )
        if history.explicit_ids and (
            asset_id is None or history.explicit_ids != {normalize_asset_identity_value(asset_id)}
        ):
            return None
        if history.incomplete_scope or history.target_scopes != {expected_scope}:
            return None
        return asset

    def asset_matches_import_identity(
        self,
        asset: Asset,
        *,
        asset_id: str | None,
        target_kind: str,
        target_ref: str | None,
        identity_evidence: AssetIdentityEvidence | None = None,
    ) -> bool:
        """Check whether persisted occurrence evidence supports an import asset identity."""
        history = identity_evidence or self.import_identity_evidence(asset.id)
        if history.asset_id != asset.id:
            raise AssetIdentityInvariantError("Identity proof belongs to another asset.")
        if not history.has_findings:
            # Manually created assets intentionally remain addressable by their
            # operator-selected key. Internal keys, however, are identity
            # claims and require persisted occurrence evidence.
            return not is_reserved_asset_storage_key(asset.asset_key)
        if not history.complete_history or history.invalid_asset_id:
            return False

        expected_scope = (
            normalize_asset_target_kind(target_kind),
            normalize_asset_identity_value(target_ref) if target_ref is not None else "",
        )
        if history.explicit_ids:
            return asset_id is not None and history.explicit_ids == {
                normalize_asset_identity_value(asset_id)
            }
        if target_ref is None or history.incomplete_scope:
            return False
        return history.target_scopes == {expected_scope}

    def evidence_proven_implicit_import_identity(
        self,
        asset: Asset,
    ) -> tuple[str, str] | None:
        """
        Return one complete implicit source-target identity for an imported asset.

        This deliberately refuses manual rows, mixed explicit/implicit history,
        incomplete evidence, and assets whose linked occurrences disagree.  It
        is used only to move a proven implicit identity out of a readable key
        that is canonically owned by a later explicit asset ID.
        """
        history = self.import_identity_evidence(asset.id)
        if (
            not history.has_findings
            or not history.complete_history
            or history.invalid_asset_id
            or history.blank_asset_id
            or history.explicit_ids
            or history.incomplete_scope
            or len(history.target_scopes) != 1
        ):
            return None
        return next(iter(history.target_scopes))

    def import_identity_evidence(self, asset_id: uuid.UUID) -> AssetIdentityEvidence:
        """Summarize all distinct identity facts once for a read-only import pass."""
        has_findings, complete = self._asset_occurrence_history_status(asset_id)
        explicit_ids: set[str] = set()
        target_scopes: set[tuple[str, str]] = set()
        invalid_id = blank_id = incomplete_scope = False
        if has_findings and complete:
            for evidence in self._iter_asset_occurrence_evidence(asset_id):
                explicit = evidence.get("asset_id")
                if explicit is not None:
                    if not isinstance(explicit, str):
                        invalid_id = True
                    elif explicit.strip():
                        explicit_ids.add(normalize_asset_identity_value(explicit))
                    else:
                        blank_id = True
                kind, ref = evidence.get("target_kind"), evidence.get("target_ref")
                if isinstance(kind, str) and kind.strip() and isinstance(ref, str) and ref.strip():
                    target_scopes.add(
                        (normalize_asset_target_kind(kind), normalize_asset_identity_value(ref))
                    )
                else:
                    incomplete_scope = True
        return AssetIdentityEvidence(
            asset_id,
            has_findings,
            complete,
            frozenset(explicit_ids),
            frozenset(target_scopes),
            invalid_id,
            blank_id,
            incomplete_scope,
        )

    def asset_is_exclusively_linked_to_finding(
        self,
        *,
        asset_id: uuid.UUID,
        finding_id: uuid.UUID,
    ) -> bool:
        """Return whether exactly one persisted finding owns this asset link."""
        linked_finding_ids = list(
            self.session.exec(select(Finding.id).where(Finding.asset_id == asset_id).limit(2)).all()
        )
        return len(linked_finding_ids) == 1 and linked_finding_ids[0] == finding_id

    def _asset_occurrence_history_status(self, asset_id: uuid.UUID) -> tuple[bool, bool]:
        """Return whether an asset has findings and every finding has evidence."""
        has_findings = (
            self.session.exec(
                select(Finding.id).where(Finding.asset_id == asset_id).limit(1)
            ).first()
            is not None
        )
        if not has_findings:
            return False, True
        missing_occurrence = self.session.exec(
            select(Finding.id)
            .outerjoin(
                FindingOccurrence,
                col(FindingOccurrence.finding_id) == col(Finding.id),
            )
            .where(
                Finding.asset_id == asset_id,
                col(FindingOccurrence.id).is_(None),
            )
            .limit(1)
        ).first()
        return True, missing_occurrence is None

    def _iter_asset_occurrence_evidence(
        self,
        asset_id: uuid.UUID,
    ) -> Iterator[Mapping[str, Any]]:
        """Stream distinct identity facts through the covering expression index."""
        statement = (
            select(*occurrence_identity_expressions(col(FindingOccurrence.evidence_json)))
            .select_from(FindingOccurrence)
            .join(Finding, col(Finding.id) == col(FindingOccurrence.finding_id))
            .where(Finding.asset_id == asset_id)
            .distinct()
            .execution_options(stream_results=True, yield_per=500)
        )
        for row in self.session.exec(statement):
            yield {
                name: json.loads(value) if value is not None else None
                for name, value in zip(OCCURRENCE_IDENTITY_FIELDS, row, strict=True)
            }

    def list_project_assets(
        self,
        project_id: uuid.UUID,
        *,
        owner: str | None = None,
        service: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Asset]:
        """Return project assets ordered for stable API output."""
        filters: list[Any] = [Asset.project_id == project_id]
        if owner and owner.strip():
            filters.append(col(Asset.owner).ilike(f"%{owner.strip()}%"))
        if service and service.strip():
            filters.append(col(Asset.business_service).ilike(f"%{service.strip()}%"))
        statement = select(Asset).where(*filters).order_by(Asset.asset_key).offset(offset)
        if limit is not None:
            statement = statement.limit(limit)
        return list(self.session.exec(statement).all())

    def list_project_assets_page(
        self,
        project_id: uuid.UUID,
        *,
        owner: str | None = None,
        service: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Asset], int]:
        """Return a bounded asset page and total count."""
        filters: list[Any] = [Asset.project_id == project_id]
        if owner and owner.strip():
            filters.append(col(Asset.owner).ilike(f"%{owner.strip()}%"))
        if service and service.strip():
            filters.append(col(Asset.business_service).ilike(f"%{service.strip()}%"))
        count_statement = select(func.count()).select_from(Asset).where(*filters)
        count = int(self.session.exec(count_statement).one())
        assets = self.list_project_assets(
            project_id,
            owner=owner,
            service=service,
            limit=limit,
            offset=offset,
        )
        return assets, count

    def finding_summaries_for_assets(
        self,
        asset_ids: Sequence[uuid.UUID],
    ) -> dict[uuid.UUID, AssetFindingSummary]:
        """Batch finding counts and rescore flags for one bounded asset page."""
        unique_ids = list(dict.fromkeys(asset_ids))
        summaries = {asset_id: AssetFindingSummary() for asset_id in unique_ids}
        for index in range(0, len(unique_ids), 500):
            statement = (
                select(
                    Finding.asset_id,
                    FindingCurrentProjection.lifecycle_overlay_json,
                )
                .outerjoin(
                    FindingCurrentProjection,
                    col(FindingCurrentProjection.finding_id) == col(Finding.id),
                )
                .where(col(Finding.asset_id).in_(unique_ids[index : index + 500]))
            )
            for asset_id, lifecycle_overlay in self.session.exec(statement).all():
                if asset_id is None:  # pragma: no cover - constrained by the IN predicate
                    continue
                previous = summaries[asset_id]
                summaries[asset_id] = AssetFindingSummary(
                    finding_count=previous.finding_count + 1,
                    rescore_needed=(
                        previous.rescore_needed
                        or _decision_evidence_rescore_needed(dict(lifecycle_overlay or {}))
                    ),
                )
        return summaries

    def update_asset(self, asset: Asset, asset_in: AssetUpdate) -> Asset:
        """Update mutable asset fields without committing the transaction."""
        update_data = asset_in.model_dump(exclude_unset=True)
        if asset_in.asset_key is not None:
            update_data["asset_key"] = validate_asset_key_update(
                asset_in.asset_key,
                current_asset_key=asset.asset_key,
            )
        asset.sqlmodel_update(update_data)
        asset.updated_at = get_datetime_utc()
        self.session.add(asset)
        self.session.flush()
        return asset

    def mark_asset_findings_rescore_needed(
        self,
        *,
        asset_id: uuid.UUID,
        changed_fields: Sequence[str],
        changed_at: datetime | None = None,
        flush: bool = True,
    ) -> int:
        """Mark findings linked to an edited asset for explicit re-score review."""
        timestamp = changed_at or get_datetime_utc()
        changed = sorted(set(changed_fields))
        statement = select(Finding).where(Finding.asset_id == asset_id)
        findings = list(self.session.exec(statement).all())
        projection_repository = FindingCurrentProjectionRepository(self.session)
        for finding in findings:
            current_payload = projection_repository.current_payload(finding.id)
            if current_payload is not None:
                updated_payload = _mark_decision_evidence_rescore_needed(
                    current_payload,
                    asset_id=asset_id,
                    changed_fields=changed,
                    changed_at=timestamp,
                )
                projection_repository.update_current_payload(
                    finding.id,
                    updated_payload,
                    flush=False,
                )
            finding.updated_at = timestamp
            self.session.add(finding)
        if flush:
            self.session.flush()
        return len(findings)

    def recalculate_asset_findings(self, asset: Asset) -> dict[str, Any]:
        """Recalculate linked finding operational scores from current asset context."""
        timestamp = get_datetime_utc()
        statement = select(Finding).where(Finding.asset_id == asset.id)
        findings = list(self.session.exec(statement).all())
        projection_repository = FindingCurrentProjectionRepository(self.session)
        cleared_flags = 0
        unreplayable_findings = 0
        scores: list[int] = []
        for finding in findings:
            finding.updated_at = timestamp
            self.session.add(finding)
            current_payload = projection_repository.current_payload(finding.id)
            operational_score = 0
            if current_payload is None or not current_payload.get("evaluation_input"):
                # Historical outputs remain readable but do not prove complete
                # inputs for a new evaluation. Never clear their stale marker.
                unreplayable_findings += 1
                if current_payload is not None:
                    current_payload = _mark_decision_evidence_rescore_needed(
                        current_payload,
                        asset_id=asset.id,
                        changed_fields=["evaluation_input_unavailable"],
                        changed_at=timestamp,
                    )
                    projection_repository.update_current_payload(finding.id, current_payload)
            else:
                updated_payload, cleared = _clear_decision_evidence_rescore_needed(
                    current_payload,
                    asset=asset,
                    recalculated_at=timestamp,
                )
                projection_repository.update_current_payload(finding.id, updated_payload)
                cleared_flags += cleared
                operational_score = int(
                    float(_decision_payload(updated_payload).get("risk_score") or 0)
                )
            scores.append(operational_score)
        self.session.flush()
        return {
            "asset_id": asset.id,
            "asset_key": asset.asset_key,
            "recalculated_findings": len(findings) - unreplayable_findings,
            "unreplayable_findings": unreplayable_findings,
            "cleared_rescore_flags": cleared_flags,
            "operational_scores": scores,
            "rescore_needed": unreplayable_findings > 0,
        }

    def finding_rescore_needed(self, finding: Finding) -> bool:
        """Return whether the latest v2 finding evidence is marked for re-score."""
        payload = FindingCurrentProjectionRepository(self.session).current_payload(finding.id)
        return payload is not None and _decision_evidence_rescore_needed(payload)

    def linked_finding_operational_scores(self, asset_id: uuid.UUID) -> list[int]:
        """Return current scores for an asset after a project-wide recomputation."""
        findings = list(
            self.session.exec(
                select(Finding).where(Finding.asset_id == asset_id).order_by(col(Finding.id))
            ).all()
        )
        evidence_by_finding = FindingCurrentProjectionRepository(
            self.session
        ).evidence_for_findings(finding.id for finding in findings)
        return [
            int(float(evidence_by_finding[finding.id].risk_score or 0))
            if finding.id in evidence_by_finding
            else 0
            for finding in findings
        ]


def _mark_decision_evidence_rescore_needed(
    payload: dict[str, Any],
    *,
    asset_id: uuid.UUID,
    changed_fields: Sequence[str],
    changed_at: datetime,
) -> dict[str, Any]:
    candidate = _decision_payload(payload)
    priority_evidence = _object_value(candidate.get("priority_evidence"))
    flags = _flag_items(priority_evidence.get("data_quality_flags"))
    flags = [flag for flag in flags if flag.get("code") != ASSET_CONTEXT_RESCORE_FLAG]
    flags.append(
        {
            "source": "asset_context",
            "code": ASSET_CONTEXT_RESCORE_FLAG,
            "severity": "warning",
            "message": (
                "Asset context changed; rerun analysis or review the operational "
                "score before relying on this priority."
            ),
            "asset_id": str(asset_id),
            "changed_fields": list(changed_fields),
            "changed_at": changed_at.isoformat(),
        }
    )
    priority_evidence["data_quality_flags"] = flags
    priority_evidence["data_quality_confidence"] = "medium"
    candidate["priority_evidence"] = priority_evidence
    return FindingDecisionEvidenceV2.model_validate(candidate).to_jsonable()


def _clear_decision_evidence_rescore_needed(
    payload: dict[str, Any],
    *,
    asset: Asset,
    recalculated_at: datetime,
) -> tuple[dict[str, Any], int]:
    candidate = _decision_payload(payload)
    priority_evidence = _object_value(candidate.get("priority_evidence"))
    flags = _flag_items(priority_evidence.get("data_quality_flags"))
    kept = [flag for flag in flags if flag.get("code") != ASSET_CONTEXT_RESCORE_FLAG]
    cleared = len(flags) - len(kept)
    priority_evidence["data_quality_flags"] = kept
    priority_evidence["raw"] = _with_asset_rescore_metadata(
        _object_value(priority_evidence.get("raw")),
        asset=asset,
        recalculated_at=recalculated_at,
    )
    candidate["priority_evidence"] = priority_evidence
    candidate["occurrence_scope"] = _with_current_asset_context(
        _object_value(candidate.get("occurrence_scope")),
        asset=asset,
    )
    candidate["occurrences"] = [
        _with_current_asset_context(_object_value(item), asset=asset)
        for item in candidate.get("occurrences", [])
        if isinstance(item, dict)
    ]
    if candidate.get("evaluation_input"):
        inputs = ScopeEvaluationInput.model_validate(candidate["evaluation_input"])
        observations = [
            item.model_copy(
                update={
                    "asset_owner": asset.owner,
                    "asset_business_service": asset.business_service,
                    "asset_environment": normalize_asset_environment(
                        _enum_value(asset.environment), warnings=[], row_number=0
                    ),
                    "asset_exposure": normalize_asset_exposure(
                        _enum_value(asset.exposure), warnings=[], row_number=0
                    ),
                    "asset_criticality": normalize_asset_criticality(
                        _enum_value(asset.criticality), warnings=[], row_number=0
                    ),
                }
            )
            for item in inputs.observations
        ]
        candidate["evaluation_input"] = inputs.model_copy(
            update={"observations": observations}
        ).model_dump(mode="json")
    candidate["risk_score"] = float(candidate.get("risk_score") or 0)
    return FindingDecisionEvidenceV2.model_validate(candidate).to_jsonable(), cleared


def _decision_evidence_rescore_needed(payload: dict[str, Any]) -> bool:
    priority_evidence = _object_value(_object_value(payload).get("priority_evidence"))
    return any(
        flag.get("code") == ASSET_CONTEXT_RESCORE_FLAG
        for flag in _flag_items(priority_evidence.get("data_quality_flags"))
    )


def _with_asset_rescore_metadata(
    raw: dict[str, Any],
    *,
    asset: Asset,
    recalculated_at: datetime,
) -> dict[str, Any]:
    updated = dict(raw)
    asset_context = _object_value(updated.get("asset_context"))
    asset_context.update(
        {
            "asset_id": str(asset.id),
            "asset_key": asset.asset_key,
            "rescore_needed": False,
            "recalculated_at": recalculated_at.isoformat(),
        }
    )
    updated["asset_context"] = asset_context
    return updated


def _with_current_asset_context(raw: dict[str, Any], *, asset: Asset) -> dict[str, Any]:
    """Materialize mutable relational context without changing source scope identity."""
    updated = dict(raw)
    updated.update(
        {
            "asset_owner": asset.owner,
            "asset_business_service": asset.business_service,
            "asset_environment": _enum_value(asset.environment),
            "asset_exposure": _enum_value(asset.exposure),
            "asset_criticality": _enum_value(asset.criticality),
        }
    )
    return updated


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _decision_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return dict(_object_value(payload))


def _object_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _flag_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]
