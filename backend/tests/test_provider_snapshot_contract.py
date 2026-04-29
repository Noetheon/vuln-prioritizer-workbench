from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_prioritizer.provider_snapshot import load_provider_snapshot


def test_provider_snapshot_missing_required_v1_fields_fails_clearly(tmp_path: Path) -> None:
    snapshot_file = tmp_path / "provider-snapshot.json"
    snapshot_file.write_text(
        json.dumps(
            {
                "items": [],
                "metadata": {
                    "artifact_kind": "provider-snapshot",
                    "generated_at": "2026-04-21T12:00:00+00:00",
                    "schema_version": "1.2.0",
                },
                "warnings": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        load_provider_snapshot(snapshot_file)

    message = str(exc_info.value)
    assert str(snapshot_file) in message
    assert "missing required metadata field(s)" in message
    assert "snapshot_format" in message
    assert "source_hashes" in message
    assert "source_metadata" in message


def test_provider_snapshot_rejects_wrong_snapshot_format(tmp_path: Path) -> None:
    snapshot_file = tmp_path / "provider-snapshot.json"
    metadata = {
        "artifact_kind": "provider-snapshot",
        "cache_dir": ".cache/vuln-prioritizer",
        "cache_enabled": True,
        "generated_at": "2026-04-21T12:00:00+00:00",
        "input_format": "cve-list",
        "input_path": None,
        "input_paths": [],
        "nvd_api_key_env": "NVD_API_KEY",
        "offline_kev_file": None,
        "output_path": str(snapshot_file),
        "requested_cves": 0,
        "schema_version": "1.2.0",
        "selected_sources": ["nvd", "epss", "kev"],
        "snapshot_format": "provider-snapshot.legacy.json",
        "source_hashes": {"nvd": None, "epss": None, "kev": None},
        "source_metadata": {},
    }
    snapshot_file.write_text(
        json.dumps({"items": [], "metadata": metadata, "warnings": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="metadata.snapshot_format must be"):
        load_provider_snapshot(snapshot_file)
