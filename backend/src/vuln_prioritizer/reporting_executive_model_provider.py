"""Provider evidence model builders for executive reports."""

from __future__ import annotations

from typing import Any

from vuln_prioritizer.reporting_executive_model_helpers import _provider_evidence_notes
from vuln_prioritizer.reporting_executive_utils import (
    _dict_value,
    _int_value,
    _provider_value,
    _short_provider_date,
    _text,
)


def _provider_freshness_rows(
    metadata: dict[str, Any],
    provider_snapshot: Any | None,
) -> list[dict[str, str]]:
    locked = "locked" if metadata.get("locked_provider_data") else "not locked"
    return [
        {
            "provider": "NVD",
            "last_sync": _short_provider_date(_provider_value(provider_snapshot, "nvd_last_sync")),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "FIRST EPSS",
            "last_sync": _short_provider_date(_provider_value(provider_snapshot, "epss_date")),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "CISA KEV",
            "last_sync": _short_provider_date(
                _provider_value(provider_snapshot, "kev_catalog_version")
            ),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "MITRE ATT&CK",
            "last_sync": "ATT&CK " + _text(metadata.get("attack_version"), default="not supplied"),
            "source_status": "enabled" if metadata.get("attack_enabled") else "not supplied",
            "freshness": _text(metadata.get("attack_domain"), default="not supplied"),
        },
    ]


def _provider_transparency_model(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    provider_snapshot: Any | None,
) -> dict[str, Any]:
    diagnostics = _dict_value(metadata.get("nvd_diagnostics"))
    sources = metadata.get("provider_snapshot_sources") or metadata.get("data_sources") or []
    source_text = (
        ", ".join(str(item) for item in sources if item) if isinstance(sources, list) else ""
    )
    nvd_diag = []
    for label, key in (
        ("Requested", "requested"),
        ("Cache hits", "cache_hits"),
        ("Network fetches", "network_fetches"),
        ("Failures", "failures"),
        ("Content hits", "content_hits"),
    ):
        if key in diagnostics:
            nvd_diag.append({"label": label, "value": str(_int_value(diagnostics.get(key)))})
    return {
        "facts": [
            {
                "label": "Selected sources",
                "value": source_text or "not supplied",
            },
            {
                "label": "Provider snapshot",
                "value": _text(metadata.get("provider_snapshot_file")),
            },
            {
                "label": "Locked provider data",
                "value": "yes" if metadata.get("locked_provider_data") else "no",
            },
            {
                "label": "NVD last sync",
                "value": _provider_value(provider_snapshot, "nvd_last_sync"),
            },
            {
                "label": "EPSS date",
                "value": _provider_value(provider_snapshot, "epss_date"),
            },
            {
                "label": "KEV catalog",
                "value": _provider_value(provider_snapshot, "kev_catalog_version"),
            },
        ],
        "diagnostics": nvd_diag,
        "notes": _provider_evidence_notes(findings),
        "commands": [
            "vuln-prioritizer analyze --attack-source ctid-json",
            "vuln-prioritizer analyze --waiver-file waivers.yml",
        ],
    }


__all__ = ["_provider_freshness_rows", "_provider_transparency_model"]
