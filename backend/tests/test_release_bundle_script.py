from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

from paths import REPO_ROOT


def test_release_bundle_script_builds_local_workbench_zip(tmp_path: Path) -> None:
    output_dir = tmp_path / "release"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_release_bundle.py",
            "--output",
            str(output_dir),
            "--version",
            "9.9.9-test",
        ],
        check=True,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        text=True,
    )

    zip_path = Path(result.stdout.strip())
    assert zip_path.is_file()
    assert zip_path.name == "vuln-prioritizer-workbench-local-9.9.9-test.zip"
    assert zip_path.with_suffix(".zip.sha256").is_file()

    prefix = "vuln-prioritizer-workbench-local-9.9.9-test/"
    with zipfile.ZipFile(zip_path) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read(f"{prefix}BUNDLE-MANIFEST.json"))

    required = {
        "README.md",
        "INSTALL.md",
        "TROUBLESHOOTING.md",
        "compose.yml",
        "compose.override.yml",
        "launch-workbench.command",
        "launch-workbench.bat",
        "scripts/launch-workbench.sh",
        "scripts/launch-workbench.ps1",
        "backend/Dockerfile",
        "frontend/Dockerfile",
        "data/demo_provider_snapshot.json",
    }
    for path in required:
        assert f"{prefix}{path}" in names

    forbidden_fragments = (
        "/.git/",
        "/.venv/",
        "/node_modules/",
        "/workbench.db",
        "/data/workbench-import-uploads/",
        "/data/workbench-reports/",
        "/data/workbench-provider-cache/",
        "/diagnostics/",
        "/dist/",
        "/build/",
    )
    assert not any(fragment in name for fragment in forbidden_fragments for name in names)
    assert manifest["schema_version"] == "release-bundle-manifest.v1"
    assert manifest["version"] == "9.9.9-test"
    assert manifest["file_count"] > len(required)
    assert all("sha256" in item for item in manifest["files"])
