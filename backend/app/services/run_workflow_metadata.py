"""Small helpers for internal workflow metadata payloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.domain.engine.security_redaction import redact_value


def merge_summary_payload(
    base: Mapping[str, Any] | None,
    **updates: Any,
) -> dict[str, Any]:
    """Merge internal workflow metadata before Evidence v2 is persisted."""
    return _merged_payload(base, updates)


def merge_error_payload(
    base: Mapping[str, Any] | None = None,
    **updates: Any,
) -> dict[str, Any]:
    """Merge internal workflow diagnostic metadata."""
    return _merged_payload(base, updates)


def redacted_workflow_summary_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return redacted internal workflow result metadata."""
    return _dict_value(redact_public_payload(_mapping_value(payload)))


def redacted_workflow_error_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return redacted internal workflow diagnostic metadata."""
    return _dict_value(redact_public_payload(_mapping_value(payload)))


def public_workflow_fields(
    result: Mapping[str, Any] | None,
    diagnostics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a compatibility-free public projection for internal workflow payloads."""
    return {
        "result": redacted_workflow_summary_payload(result),
        "diagnostics": redacted_workflow_error_payload(diagnostics),
    }


def redact_public_payload(value: Any) -> Any:
    """Redact secrets and local paths from public workflow payload values."""
    redacted, _paths = redact_value(value)
    return redacted


def _merged_payload(base: Mapping[str, Any] | None, updates: Mapping[str, Any]) -> dict[str, Any]:
    payload = _mapping_value(base)
    payload.update({key: value for key, value in updates.items() if value is not None})
    return payload


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _mapping_value(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}
