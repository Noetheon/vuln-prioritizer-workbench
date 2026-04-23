"""Provider snapshot export and replay helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from vuln_prioritizer.models import ProviderSnapshotReport

if TYPE_CHECKING:
    from pydantic import BaseModel

    from vuln_prioritizer.models import ProviderSnapshotItem


def generate_provider_snapshot_json(report: ProviderSnapshotReport) -> str:
    """Serialize a provider snapshot report as stable JSON."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def load_provider_snapshot(path: Path) -> ProviderSnapshotReport:
    """Load and validate a provider snapshot artifact."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc.msg}.") from exc

    try:
        return ProviderSnapshotReport.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"{path} is not a valid provider snapshot: {exc}") from exc


def snapshot_items_by_cve(report: ProviderSnapshotReport) -> dict[str, ProviderSnapshotItem]:
    """Index a provider snapshot by CVE identifier."""
    return {item.cve_id: item for item in report.items}


def resolve_snapshot_provider_data(
    report: ProviderSnapshotReport,
    *,
    source_name: str,
    cve_ids: list[str],
) -> tuple[dict[str, BaseModel], list[str]]:
    """Resolve per-provider snapshot coverage for the requested CVEs."""
    items_by_cve = snapshot_items_by_cve(report)
    selected_sources = set(report.metadata.selected_sources)
    resolved: dict[str, BaseModel] = {}
    missing: list[str] = []

    for cve_id in cve_ids:
        item = items_by_cve.get(cve_id)
        provider_value = None if item is None else getattr(item, source_name, None)
        if provider_value is None:
            if source_name in selected_sources:
                missing.append(cve_id)
            else:
                missing.append(cve_id)
            continue
        resolved[cve_id] = provider_value

    return resolved, missing
