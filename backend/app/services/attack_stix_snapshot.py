"""Versioned ATT&CK STIX snapshot import services."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlmodel import Session, col, select

from app.domain.engine.providers.attack_stix import AttackStixProvider
from app.models import (
    AttackStixMitigation,
    AttackStixSnapshot,
    AttackStixTactic,
    AttackStixTechnique,
    AttackStixTechniqueMitigation,
)
from app.models.base import get_datetime_utc
from app.repositories import RunRepository


@dataclass(frozen=True)
class AttackStixSnapshotImportResult:
    """Import result for one ATT&CK STIX snapshot."""

    snapshot_id: uuid.UUID
    provider_snapshot_id: uuid.UUID | None
    attack_version: str
    domain: str
    stix_spec_version: str | None
    bundle_sha256: str
    tactic_count: int
    technique_count: int
    mitigation_count: int
    mitigation_relationship_count: int
    warnings: list[str] = field(default_factory=list)
    created: bool = False


@dataclass(frozen=True)
class AttackTechniqueCatalogValidation:
    """Technique-ID validation result against a persisted ATT&CK snapshot."""

    snapshot_id: uuid.UUID
    attack_version: str
    domain: str
    valid_technique_ids: list[str]
    missing_technique_ids: list[str]
    revoked_or_deprecated_technique_ids: list[str]


def import_attack_stix_snapshot(
    session: Session,
    source_path: Path,
) -> AttackStixSnapshotImportResult:
    """Import a pinned ATT&CK STIX bundle into versioned catalog tables."""
    raw_content = source_path.read_bytes()
    try:
        payload = json.loads(raw_content.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"ATT&CK STIX snapshot is not valid JSON: {source_path}") from exc

    parsed = AttackStixProvider().load_snapshot_payload(
        payload,
        source_path=source_path,
        raw_content=raw_content,
    )
    bundle_sha256 = str(parsed.metadata["metadata_file_sha256"])
    existing = _snapshot_by_hash(session, bundle_sha256)
    if existing is not None:
        return _existing_result(session, existing, warnings=parsed.warnings)

    attack_version = parsed.metadata.get("attack_version") or "unknown"
    domain = parsed.metadata.get("domain") or "unknown"
    stix_spec_version = parsed.metadata.get("stix_spec_version")
    imported_at = get_datetime_utc()
    source_metadata: dict[str, Any] = {
        "provider": "mitre-attack-stix",
        "metadata_format": parsed.metadata.get("metadata_format"),
        "attack_version": attack_version,
        "domain": domain,
        "stix_spec_version": stix_spec_version,
        "bundle_sha256": bundle_sha256,
        "source_path": str(source_path),
        "generated_at": imported_at.isoformat(),
        "selected_sources": ["attack_stix"],
        "snapshot_mode": "attack-stix",
        "missing": False,
        "object_counts": parsed.object_counts,
        "warnings": parsed.warnings,
        "tactic_count": len(parsed.tactics),
        "technique_count": len(parsed.techniques),
        "mitigation_count": len(parsed.mitigations),
        "mitigation_relationship_count": len(parsed.mitigation_relationships),
    }
    provider_snapshot = RunRepository(session).get_or_create_provider_snapshot(
        content_hash=bundle_sha256,
        source_hashes_json={"attack_stix": bundle_sha256},
        source_metadata_json=source_metadata,
    )
    snapshot = AttackStixSnapshot(
        attack_version=attack_version,
        domain=domain,
        stix_spec_version=stix_spec_version,
        bundle_sha256=bundle_sha256,
        source_path=str(source_path),
        object_counts_json=parsed.object_counts,
        source_metadata_json=source_metadata,
        provider_snapshot_id=provider_snapshot.id,
        created_at=imported_at,
        updated_at=imported_at,
    )
    session.add(snapshot)
    session.flush()

    for tactic in parsed.tactics.values():
        session.add(
            AttackStixTactic(
                snapshot_id=snapshot.id,
                stix_id=tactic.stix_id,
                tactic_id=tactic.tactic_id,
                name=tactic.name,
                short_name=tactic.short_name,
                description=tactic.description,
                url=tactic.url,
                revoked=tactic.revoked,
                deprecated=tactic.deprecated,
            )
        )
    for technique in parsed.techniques.values():
        session.add(
            AttackStixTechnique(
                snapshot_id=snapshot.id,
                stix_id=technique.stix_id,
                technique_id=technique.technique_id,
                name=technique.name,
                tactic_ids_json=technique.tactic_ids,
                tactic_short_names_json=technique.tactic_short_names,
                description=technique.description,
                url=technique.url,
                revoked=technique.revoked,
                deprecated=technique.deprecated,
                is_subtechnique=technique.is_subtechnique,
            )
        )
    for mitigation in parsed.mitigations.values():
        session.add(
            AttackStixMitigation(
                snapshot_id=snapshot.id,
                stix_id=mitigation.stix_id,
                mitigation_id=mitigation.mitigation_id,
                name=mitigation.name,
                description=mitigation.description,
                url=mitigation.url,
                revoked=mitigation.revoked,
                deprecated=mitigation.deprecated,
            )
        )
    for relationship in parsed.mitigation_relationships:
        session.add(
            AttackStixTechniqueMitigation(
                snapshot_id=snapshot.id,
                relationship_id=relationship.relationship_id,
                technique_id=relationship.technique_id,
                mitigation_id=relationship.mitigation_id,
                description=relationship.description,
            )
        )

    session.flush()
    return AttackStixSnapshotImportResult(
        snapshot_id=snapshot.id,
        provider_snapshot_id=provider_snapshot.id,
        attack_version=attack_version,
        domain=domain,
        stix_spec_version=stix_spec_version,
        bundle_sha256=bundle_sha256,
        tactic_count=len(parsed.tactics),
        technique_count=len(parsed.techniques),
        mitigation_count=len(parsed.mitigations),
        mitigation_relationship_count=len(parsed.mitigation_relationships),
        warnings=parsed.warnings,
        created=True,
    )


def validate_attack_technique_ids(
    session: Session,
    technique_ids: list[str],
    *,
    snapshot_id: uuid.UUID | None = None,
) -> AttackTechniqueCatalogValidation:
    """Validate ATT&CK technique IDs against the latest or selected STIX snapshot."""
    snapshot = _snapshot_for_validation(session, snapshot_id=snapshot_id)
    normalized_ids = sorted({value.strip() for value in technique_ids if value.strip()})
    if not normalized_ids:
        return AttackTechniqueCatalogValidation(
            snapshot_id=snapshot.id,
            attack_version=snapshot.attack_version,
            domain=snapshot.domain,
            valid_technique_ids=[],
            missing_technique_ids=[],
            revoked_or_deprecated_technique_ids=[],
        )

    rows = session.exec(
        select(AttackStixTechnique).where(
            AttackStixTechnique.snapshot_id == snapshot.id,
            col(AttackStixTechnique.technique_id).in_(normalized_ids),
        )
    ).all()
    by_id = {row.technique_id: row for row in rows}
    valid_ids = sorted(by_id)
    return AttackTechniqueCatalogValidation(
        snapshot_id=snapshot.id,
        attack_version=snapshot.attack_version,
        domain=snapshot.domain,
        valid_technique_ids=valid_ids,
        missing_technique_ids=[
            technique_id for technique_id in normalized_ids if technique_id not in by_id
        ],
        revoked_or_deprecated_technique_ids=[
            technique_id
            for technique_id, row in sorted(by_id.items())
            if row.revoked or row.deprecated
        ],
    )


def _snapshot_for_validation(
    session: Session,
    *,
    snapshot_id: uuid.UUID | None,
) -> AttackStixSnapshot:
    if snapshot_id is not None:
        snapshot = session.get(AttackStixSnapshot, snapshot_id)
        if snapshot is None:
            raise LookupError(f"ATT&CK STIX snapshot not found: {snapshot_id}")
        return snapshot

    snapshot = session.exec(
        select(AttackStixSnapshot).order_by(col(AttackStixSnapshot.created_at).desc())
    ).first()
    if snapshot is None:
        raise LookupError("No ATT&CK STIX snapshot has been imported.")
    return snapshot


def _snapshot_by_hash(session: Session, bundle_sha256: str) -> AttackStixSnapshot | None:
    return session.exec(
        select(AttackStixSnapshot).where(AttackStixSnapshot.bundle_sha256 == bundle_sha256)
    ).first()


def _existing_result(
    session: Session,
    snapshot: AttackStixSnapshot,
    *,
    warnings: list[str],
) -> AttackStixSnapshotImportResult:
    return AttackStixSnapshotImportResult(
        snapshot_id=snapshot.id,
        provider_snapshot_id=snapshot.provider_snapshot_id,
        attack_version=snapshot.attack_version,
        domain=snapshot.domain,
        stix_spec_version=snapshot.stix_spec_version,
        bundle_sha256=snapshot.bundle_sha256,
        tactic_count=_count_rows(session, AttackStixTactic, snapshot.id),
        technique_count=_count_rows(session, AttackStixTechnique, snapshot.id),
        mitigation_count=_count_rows(session, AttackStixMitigation, snapshot.id),
        mitigation_relationship_count=_count_rows(
            session,
            AttackStixTechniqueMitigation,
            snapshot.id,
        ),
        warnings=warnings,
        created=False,
    )


def _count_rows(session: Session, model: Any, snapshot_id: uuid.UUID) -> int:
    return len(session.exec(select(model).where(model.snapshot_id == snapshot_id)).all())
