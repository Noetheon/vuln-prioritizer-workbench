"""Converge the current queue using compact keys and rank-only writes."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session, col, select

from app.decision_core.current_queue import decision_sort_key
from app.models import Finding, FindingCurrentProjection
from app.repositories.current_projections import FindingCurrentProjectionRepository

_BATCH_SIZE = 250


def sync_unchanged_project_ranks(
    session: Session,
    project_id: uuid.UUID,
    *,
    changed_finding_ids: set[uuid.UUID] | None = None,
    fallback_keys: dict[uuid.UUID, list[Any]] | None = None,
    require_complete: bool = True,
) -> bool:
    """
    Rank existing decisions without hydrating their evidence or evaluating them.

    A migrated projection may have no key yet. Hydrate those rows once, declining
    before any writes if an unevaluated scope remains. The caller owns the project
    decision lock; rank updates and input publication are one transaction.
    """
    missing = session.exec(
        select(Finding.id)
        .outerjoin(FindingCurrentProjection, col(FindingCurrentProjection.finding_id) == Finding.id)
        .where(Finding.project_id == project_id, col(FindingCurrentProjection.finding_id).is_(None))
        .limit(1)
    ).first()
    if missing is not None and require_complete:
        return False
    repository = FindingCurrentProjectionRepository(session)
    rows = session.exec(
        select(
            FindingCurrentProjection.finding_id,
            FindingCurrentProjection.operational_sort_key_json,
            FindingCurrentProjection.operational_rank,
        ).where(FindingCurrentProjection.project_id == project_id)
    ).all()
    supplied = fallback_keys or {}
    missing_ids = [
        finding_id for finding_id, key, _ in rows if key is None and finding_id not in supplied
    ]
    restored: dict[uuid.UUID, list[Any]] = {}
    for offset in range(0, len(missing_ids), _BATCH_SIZE):
        evidence = repository.evidence_for_findings(missing_ids[offset : offset + _BATCH_SIZE])
        for finding_id, item in evidence.items():
            key = decision_sort_key(item)
            if key is None:
                return False
            restored[finding_id] = key
    candidates = [
        (
            _as_tuple(
                key if key is not None else restored.get(finding_id, supplied.get(finding_id))
            ),
            finding_id,
            previous_rank,
        )
        for finding_id, key, previous_rank in rows
    ]
    candidates.sort(key=lambda item: (*item[0], str(item[1])))
    changes = {
        finding_id: rank
        for rank, (_, finding_id, previous_rank) in enumerate(candidates, 1)
        if previous_rank != rank
    }
    repository.update_queue_ranks(changes, restored_keys=restored)
    if changed_finding_ids is not None:
        changed_finding_ids.update(changes)
    return True


def _as_tuple(value: Any) -> Any:
    return tuple(_as_tuple(item) for item in value) if isinstance(value, (list, tuple)) else value
