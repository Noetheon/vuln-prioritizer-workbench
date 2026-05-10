"""Small audit helpers for Workbench security and lifecycle events."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlmodel import Session

from app.models import AuditEvent, AuditEventStatus, User
from app.models.api_tokens import api_token_id
from app.repositories import AuditEventRepository
from vuln_prioritizer.security_redaction import redact_value

_MAX_AUDIT_DETAIL_JSON_BYTES = 4096
_MAX_AUDIT_STRING_CHARS = 1024
_MAX_AUDIT_KEY_CHARS = 128
_MAX_AUDIT_COLLECTION_ITEMS = 50


def record_audit_event(
    session: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID | str | None = None,
    status: AuditEventStatus = "success",
    actor: User | None = None,
    project_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditEvent:
    """Persist a redacted audit event without committing the transaction."""
    redacted_detail: dict[str, Any] = {}
    if detail:
        redacted_value, _paths = redact_value(detail)
        if isinstance(redacted_value, dict):
            encoded = jsonable_encoder(redacted_value)
            redacted_detail = _truncate_audit_detail(encoded) if isinstance(encoded, dict) else {}
    return AuditEventRepository(session).create_audit_event(
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        status=status,
        actor_user_id=actor.id if actor is not None else None,
        project_id=project_id,
        api_token_id=api_token_id(actor) if actor is not None else None,
        detail=redacted_detail,
    )


def _truncate_audit_detail(detail: dict[str, Any]) -> dict[str, Any]:
    bounded = _truncate_audit_value(detail)
    bounded_detail = dict(bounded) if isinstance(bounded, dict) else {}
    if _audit_detail_size(bounded_detail) <= _MAX_AUDIT_DETAIL_JSON_BYTES:
        return bounded_detail
    return _audit_preview_detail(_audit_detail_json(bounded_detail))


def _truncate_audit_value(value: Any) -> Any:
    if isinstance(value, str):
        return value[:_MAX_AUDIT_STRING_CHARS]
    if isinstance(value, Mapping):
        bounded: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_AUDIT_COLLECTION_ITEMS:
                bounded["truncated"] = True
                bounded["omitted_keys"] = len(value) - _MAX_AUDIT_COLLECTION_ITEMS
                break
            bounded[str(key)[:_MAX_AUDIT_KEY_CHARS]] = _truncate_audit_value(item)
        return bounded
    if isinstance(value, (list, tuple)):
        bounded_items = [
            _truncate_audit_value(item) for item in value[:_MAX_AUDIT_COLLECTION_ITEMS]
        ]
        if len(value) > _MAX_AUDIT_COLLECTION_ITEMS:
            bounded_items.append(
                {
                    "truncated": True,
                    "omitted_items": len(value) - _MAX_AUDIT_COLLECTION_ITEMS,
                }
            )
        return bounded_items
    return value


def _audit_preview_detail(serialized_detail: str) -> dict[str, Any]:
    for max_chars in (2048, 1024, 512, 256, 128, 64):
        candidate: dict[str, Any] = {
            "truncated": True,
            "preview": serialized_detail[:max_chars],
        }
        if _audit_detail_size(candidate) <= _MAX_AUDIT_DETAIL_JSON_BYTES:
            return candidate
    return {"truncated": True}


def _audit_detail_size(detail: dict[str, Any]) -> int:
    return len(_audit_detail_json(detail).encode("utf-8"))


def _audit_detail_json(detail: dict[str, Any]) -> str:
    return json.dumps(detail, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
