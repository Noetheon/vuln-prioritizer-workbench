"""Evidence bundle verification response helpers."""

from __future__ import annotations

from typing import Any


def _evidence_bundle_verification_payload(
    metadata: Any,
    summary: Any,
    items: list[Any],
    *,
    display_path: str | None = None,
) -> dict[str, Any]:
    metadata_payload = metadata.model_dump(mode="json")
    if display_path is not None:
        metadata_payload["bundle_path"] = display_path
    return {
        "metadata": metadata_payload,
        "summary": summary.model_dump(mode="json"),
        "items": [item.model_dump(mode="json") for item in items],
    }


__all__ = ["_evidence_bundle_verification_payload"]
