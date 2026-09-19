"""Deterministic SBOM inventory and an actual offline scanner test process."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

from utils.import_contracts import configure_upload_dir
from utils.workbench_env import WorkbenchApiEnv


def configure_scanner(env: WorkbenchApiEnv, tmp_path: Path, matches: list[dict]) -> Path:
    root = configure_upload_dir(env, tmp_path)
    report = {
        "matches": matches,
        "descriptor": {
            "name": "grype",
            "version": "0.110.0",
            "db": {
                "built": "2026-09-19T00:00:00Z",
                "checksum": "sha256:" + "a" * 64,
                "schemaVersion": "6.0.0",
                "valid": True,
            },
        },
    }
    executable = tmp_path / "grype"
    executable.write_text(f"#!{Path(sys.executable).resolve()}\nprint({json.dumps(report)!r})\n")
    executable.chmod(0o755)
    env.client.app.state.workbench_settings = replace(
        env.client.app.state.workbench_settings,
        SBOM_GRYPE_EXECUTABLE=str(executable),
        PROVIDER_CACHE_DIR=str(tmp_path / "cache"),
    )
    return root


def sbom_content() -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                }
            ],
        }
    ).encode()


def vulnerability_match(*, with_cve: bool = True) -> dict:
    return {
        "vulnerability": {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "severity": "Critical",
            "fix": {"versions": ["2.17.1"]},
        },
        "relatedVulnerabilities": [{"id": "CVE-2021-44228"}] if with_cve else [],
        "artifact": {
            "name": "log4j-core",
            "version": "2.14.1",
            "type": "java-archive",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        },
    }
