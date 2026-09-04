"""Batch lookup helpers for Workbench import persistence."""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy import or_
from sqlmodel import Session, col, select

from app.domain.asset_identity import (
    normalize_asset_identity_value,
    normalize_asset_target_kind,
)
from app.models import (
    Asset,
    Component,
    Finding,
    FindingCurrentProjection,
    FindingOccurrence,
    Vulnerability,
)

_LEGACY_FINDING_DEDUP_PREFIXES = ("vpw019:", "vpw-finding-scope-v1:")
LegacyFindingIdentity = tuple[uuid.UUID, uuid.UUID | None, str, str | None]
LegacyFindingBaseIdentity = tuple[uuid.UUID, uuid.UUID | None]


@dataclass(frozen=True, slots=True)
class PersistedFindingAssetContext:
    """Existing finding, relational asset, and current decision projection for one scope."""

    finding: Finding
    asset: Asset | None
    current_projection: FindingCurrentProjection | None


@dataclass(frozen=True, slots=True)
class LegacyFindingIdentityLookup:
    """Evidence-proven legacy aliases plus identities that cannot be selected safely."""

    matches: dict[LegacyFindingIdentity, Finding]
    ambiguous_identities: frozenset[LegacyFindingIdentity]
    ambiguous_bases: frozenset[LegacyFindingBaseIdentity]


def _project_has_findings(*, session: Session, project_id: uuid.UUID) -> bool:
    """Return whether persisted-scope hydration can possibly match this project."""
    return (
        session.exec(select(Finding.id).where(Finding.project_id == project_id).limit(1)).first()
        is not None
    )


def _existing_finding_asset_context_by_dedup_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    dedup_keys: list[str],
) -> dict[str, PersistedFindingAssetContext]:
    """Batch-load the persisted asset and current projection for matching finding scopes."""
    contexts: dict[str, PersistedFindingAssetContext] = {}
    for chunk in _chunks(sorted(set(dedup_keys)), size=500):
        statement = (
            select(Finding, Asset, FindingCurrentProjection)
            .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
            .outerjoin(
                FindingCurrentProjection,
                col(FindingCurrentProjection.finding_id) == col(Finding.id),
            )
            .where(
                Finding.project_id == project_id,
                col(Finding.dedup_key).in_(chunk),
            )
        )
        for finding, asset, projection in session.exec(statement).all():
            contexts[finding.dedup_key] = PersistedFindingAssetContext(
                finding=finding,
                asset=asset,
                current_projection=projection,
            )
    return contexts


def _existing_findings_by_dedup_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    dedup_keys: list[str],
) -> dict[str, Finding]:
    """Load existing project findings for a bulk import without per-row lookups."""
    if not dedup_keys:
        return {}
    findings: dict[str, Finding] = {}
    for chunk in _chunks(sorted(set(dedup_keys)), size=500):
        statement = select(Finding).where(
            Finding.project_id == project_id,
            col(Finding.dedup_key).in_(chunk),
        )
        for finding in session.exec(statement).all():
            findings[finding.dedup_key] = finding
    return findings


def _existing_legacy_findings_by_identity(
    *,
    session: Session,
    project_id: uuid.UUID,
    cves: list[str],
) -> dict[LegacyFindingIdentity, Finding]:
    """Load only unambiguous legacy rows whose occurrence evidence proves the scope."""
    return _legacy_finding_identity_lookup(
        session=session,
        project_id=project_id,
        cves=cves,
    ).matches


def _legacy_finding_identity_lookup(
    *,
    session: Session,
    project_id: uuid.UUID,
    cves: list[str],
) -> LegacyFindingIdentityLookup:
    """Resolve legacy aliases and retain enough ambiguity evidence to fail safely."""
    if not cves:
        return LegacyFindingIdentityLookup(
            matches={},
            ambiguous_identities=frozenset(),
            ambiguous_bases=frozenset(),
        )
    candidates: list[Finding] = []
    for chunk in _chunks(sorted(set(cves)), size=500):
        statement = (
            select(Finding)
            .where(
                Finding.project_id == project_id,
                col(Finding.cve_id).in_(chunk),
                or_(
                    *(
                        col(Finding.dedup_key).startswith(prefix)
                        for prefix in _LEGACY_FINDING_DEDUP_PREFIXES
                    )
                ),
            )
            .order_by(col(Finding.created_at), col(Finding.id))
        )
        candidates.extend(session.exec(statement).all())
    if not candidates:
        return LegacyFindingIdentityLookup(
            matches={},
            ambiguous_identities=frozenset(),
            ambiguous_bases=frozenset(),
        )

    target_scopes_by_finding: defaultdict[uuid.UUID, set[tuple[str, str | None]]] = defaultdict(set)
    explicit_asset_ids_by_finding: defaultdict[uuid.UUID, set[str]] = defaultdict(set)
    incomplete_scope_evidence: set[uuid.UUID] = set()
    candidate_ids = [candidate.id for candidate in candidates]
    for id_chunk in [
        candidate_ids[index : index + 500] for index in range(0, len(candidate_ids), 500)
    ]:
        occurrence_statement = select(FindingOccurrence).where(
            col(FindingOccurrence.finding_id).in_(id_chunk)
        )
        for occurrence in session.exec(occurrence_statement).all():
            evidence = occurrence.evidence_json
            kind_value = evidence.get("target_kind")
            target_ref_value = evidence.get("target_ref")
            asset_id_value = evidence.get("asset_id")
            if (
                kind_value is not None
                and not isinstance(kind_value, str)
                or target_ref_value is not None
                and not isinstance(target_ref_value, str)
                or asset_id_value is not None
                and not isinstance(asset_id_value, str)
            ):
                incomplete_scope_evidence.add(occurrence.finding_id)
                continue
            target_kind = (
                normalize_asset_target_kind(kind_value)
                if isinstance(kind_value, str) and kind_value.strip()
                else "generic"
            )
            target_ref = (
                normalize_asset_identity_value(target_ref_value)
                if isinstance(target_ref_value, str) and target_ref_value.strip()
                else (
                    normalize_asset_identity_value(asset_id_value)
                    if isinstance(asset_id_value, str) and asset_id_value.strip()
                    else None
                )
            )
            target_scopes_by_finding[occurrence.finding_id].add((target_kind, target_ref))
            if isinstance(asset_id_value, str) and asset_id_value.strip():
                explicit_asset_ids_by_finding[occurrence.finding_id].add(
                    normalize_asset_identity_value(asset_id_value)
                )

    candidates_by_identity: defaultdict[LegacyFindingIdentity, list[Finding]] = defaultdict(list)
    ambiguous_bases: set[LegacyFindingBaseIdentity] = set()
    for finding in candidates:
        if finding.id in incomplete_scope_evidence:
            ambiguous_bases.add((finding.vulnerability_id, finding.component_id))
            continue
        target_scopes = target_scopes_by_finding.get(finding.id, set())
        if len(target_scopes) != 1:
            ambiguous_bases.add((finding.vulnerability_id, finding.component_id))
            continue
        target_kind, target_ref = next(iter(target_scopes))
        candidates_by_identity[
            (
                finding.vulnerability_id,
                finding.component_id,
                target_kind,
                target_ref,
            )
        ].append(finding)
    matches = {
        identity: matched[0]
        for identity, matched in candidates_by_identity.items()
        if len(matched) == 1
        or _legacy_candidates_are_semantically_equivalent(
            matched,
            explicit_asset_ids_by_finding=explicit_asset_ids_by_finding,
        )
    }
    ambiguous_identities = frozenset(
        identity
        for identity, matched in candidates_by_identity.items()
        if len(matched) > 1
        and not _legacy_candidates_are_semantically_equivalent(
            matched,
            explicit_asset_ids_by_finding=explicit_asset_ids_by_finding,
        )
    )
    return LegacyFindingIdentityLookup(
        matches=matches,
        ambiguous_identities=ambiguous_identities,
        ambiguous_bases=frozenset(ambiguous_bases),
    )


def _legacy_candidates_are_semantically_equivalent(
    candidates: list[Finding],
    *,
    explicit_asset_ids_by_finding: dict[uuid.UUID, set[str]],
) -> bool:
    """
    Recognize history-safe aliases created by canonical FK convergence.

    The component/target dimensions are already identical because callers group
    by ``LegacyFindingIdentity``.  A deterministic oldest-row survivor is safe
    only when the remaining explicit and relational asset evidence does not
    contradict that identity.  Losing rows remain untouched as historical
    aliases; the next v2 import promotes only the selected survivor in place.
    """
    relational_asset_ids = {candidate.asset_id for candidate in candidates}
    if len(relational_asset_ids) != 1:
        return False

    explicit_sets = [
        explicit_asset_ids_by_finding.get(candidate.id, set()) for candidate in candidates
    ]
    if any(len(values) > 1 for values in explicit_sets):
        return False
    explicit_asset_ids = set().union(*explicit_sets)
    if len(explicit_asset_ids) > 1:
        return False
    if explicit_asset_ids and None in relational_asset_ids:
        # With no relational corroboration, a missing explicit ID on one alias
        # cannot prove that all rows represented the same named asset.
        return all(explicit_sets)
    return True


def _existing_assets_by_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    asset_keys: list[str],
) -> dict[str, Asset]:
    if not asset_keys:
        return {}
    assets: dict[str, Asset] = {}
    for chunk in _chunks(sorted(set(asset_keys)), size=500):
        statement = select(Asset).where(
            Asset.project_id == project_id,
            col(Asset.asset_key).in_(chunk),
        )
        for asset in session.exec(statement).all():
            assets[asset.asset_key] = asset
    return assets


def _existing_vulnerabilities_by_cve(
    *,
    session: Session,
    cves: list[str],
) -> dict[str, Vulnerability]:
    if not cves:
        return {}
    vulnerabilities: dict[str, Vulnerability] = {}
    for chunk in _chunks(sorted(set(cves)), size=500):
        statement = select(Vulnerability).where(col(Vulnerability.cve_id).in_(chunk))
        for vulnerability in session.exec(statement).all():
            vulnerabilities[vulnerability.cve_id] = vulnerability
    return vulnerabilities


def _existing_components_by_identity_key(
    *,
    session: Session,
    identity_keys: list[str],
) -> dict[str, Component]:
    """Batch-load canonical component identities used by pre-analysis hydration."""
    components: dict[str, Component] = {}
    for chunk in _chunks(sorted(set(identity_keys)), size=500):
        statement = select(Component).where(col(Component.identity_key).in_(chunk))
        for component in session.exec(statement).all():
            components[component.identity_key] = component
    return components


def _chunks(values: list[str], *, size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _chunks_any(values: list[dict[str, Any]], *, size: int) -> list[list[dict[str, Any]]]:
    return [values[index : index + size] for index in range(0, len(values), size)]
