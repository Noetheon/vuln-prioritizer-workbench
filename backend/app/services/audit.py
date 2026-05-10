"""Small audit helpers for Workbench security and lifecycle events."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlmodel import Session

from app.models import AuditEvent, AuditEventStatus, User
from app.models.api_tokens import api_token_id
from app.repositories import AuditEventRepository
from vuln_prioritizer.security_redaction import redact_value

_MAX_AUDIT_DETAIL_JSON_BYTES = 4096


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
    serialized = json.dumps(detail, separators=(",", ":"), ensure_ascii=False)
    if len(serialized.encode("utf-8")) <= _MAX_AUDIT_DETAIL_JSON_BYTES:
        return detail
    for max_chars in (512, 256, 128, 64):
        candidate = {"truncated": True, "preview": serialized[:max_chars]}
        if len(json.dumps(candidate, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) <= _MAX_AUDIT_DETAIL_JSON_BYTES:
            return candidate
    return {"truncated": True}
