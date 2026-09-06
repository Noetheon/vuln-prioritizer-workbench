from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
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
    assert manifest["source_selection"] == "git_index"
    assert manifest["file_count"] > len(required)
    assert all("sha256" in item for item in manifest["files"])


def _source_tree(tmp_path: Path, *, git: bool = True) -> Path:
    root = tmp_path / "source"
    (root / "scripts").mkdir(parents=True)
    shutil.copyfile(
        REPO_ROOT / "scripts" / "build_release_bundle.py",
        root / "scripts" / "build_release_bundle.py",
    )
    (root / "README.md").write_text("Synthetic source fixture.\n", encoding="utf-8")
    (root / ".env.example").write_text("EXAMPLE=placeholder\n", encoding="utf-8")
    (root / "backend").mkdir()
    (root / "backend" / "entry.py").write_text("print('fixture')\n", encoding="utf-8")
    if git:
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
    return root


def _build_source(root: Path, *, manifest: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(root / "scripts" / "build_release_bundle.py"),
        "--output",
        "release-output",
        "--version",
        "1.0.0-fixture",
    ]
    if manifest is not None:
        command.extend(["--source-manifest", str(manifest)])
    return subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)


def test_bundle_uses_tracked_inputs_and_excludes_local_or_runtime_files(tmp_path: Path) -> None:
    root = _source_tree(tmp_path)
    private_paths = [
        "backend/.env",
        "frontend/.env.local",
        "docs/private-audit.md",
        "data/custom-local-export.json",
        "data/workbench-import-uploads/private.csv",
    ]
    for name in private_paths:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("SYNTHETIC-PRIVATE-CONTENT", encoding="utf-8")
    # Explicit runtime exclusions apply even if one was accidentally staged.
    subprocess.run(
        ["git", "add", "backend/.env", "frontend/.env.local", private_paths[-1]],
        cwd=root,
        check=True,
    )
    result = _build_source(root)
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(result.stdout.strip()) as archive:
        manifest_name = next(
            name for name in archive.namelist() if name.endswith("/BUNDLE-MANIFEST.json")
        )
        manifest = json.loads(archive.read(manifest_name))
        assert {item["path"] for item in manifest["files"]} == {
            ".env.example",
            "README.md",
            "backend/entry.py",
            "scripts/build_release_bundle.py",
        }
        prefix = manifest_name.removesuffix("BUNDLE-MANIFEST.json")
        for item in manifest["files"]:
            content = archive.read(prefix + item["path"])
            assert item["size"] == len(content)
            assert item["sha256"] == hashlib.sha256(content).hexdigest()
            assert b"SYNTHETIC-PRIVATE-CONTENT" not in content


@pytest.mark.parametrize("kind", ["tracked_symlink", "replaced_file", "replaced_directory"])
def test_bundle_rejects_symlink_sources(tmp_path: Path, kind: str) -> None:
    root = _source_tree(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    (external / "entry.py").write_text("SYNTHETIC-PRIVATE-CONTENT", encoding="utf-8")
    if kind == "replaced_directory":
        shutil.rmtree(root / "backend")
        (root / "backend").symlink_to(external, target_is_directory=True)
    else:
        (root / "backend" / "entry.py").unlink()
        (root / "backend" / "entry.py").symlink_to(external / "entry.py")
        if kind == "tracked_symlink":
            subprocess.run(["git", "add", "backend/entry.py"], cwd=root, check=True)
    result = _build_source(root)
    assert result.returncode != 0
    assert "regular file" in result.stderr or "symlinks" in result.stderr
    assert not list((root / "release-output").glob("*.zip"))


def test_bundle_rejects_missing_tracked_source(tmp_path: Path) -> None:
    root = _source_tree(tmp_path)
    (root / "backend" / "entry.py").unlink()
    result = _build_source(root)
    assert result.returncode != 0
    assert "entry.py" in result.stderr
    assert not list((root / "release-output").glob("*.zip"))


def test_source_archive_requires_explicit_manifest(tmp_path: Path) -> None:
    result = _build_source(_source_tree(tmp_path, git=False))
    assert result.returncode != 0
    assert "Git index or an explicit --source-manifest" in result.stderr


def _extracted_source(tmp_path: Path) -> Path:
    result = _build_source(_source_tree(tmp_path))
    assert result.returncode == 0, result.stderr
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(result.stdout.strip()) as archive:
        archive.extractall(extracted)
    return extracted / "vuln-prioritizer-workbench-local-1.0.0-fixture"


def test_verified_source_manifest_supports_repackaging_without_git(tmp_path: Path) -> None:
    root = _extracted_source(tmp_path)
    (root / "backend" / "local-note.txt").write_text("SYNTHETIC-PRIVATE-CONTENT", encoding="utf-8")
    result = _build_source(root, manifest=root / "BUNDLE-MANIFEST.json")
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(result.stdout.strip()) as archive:
        assert not any(name.endswith("/local-note.txt") for name in archive.namelist())
        manifest = json.loads(
            archive.read(
                next(name for name in archive.namelist() if name.endswith("/BUNDLE-MANIFEST.json"))
            )
        )
    assert manifest["source_selection"] == "verified_manifest"


def test_manifest_content_mismatch_preserves_previous_archive(tmp_path: Path) -> None:
    root = _extracted_source(tmp_path)
    output = root / "release-output"
    output.mkdir()
    previous = output / "vuln-prioritizer-workbench-local-1.0.0-fixture.zip"
    previous.write_bytes(b"previous release must remain unchanged")
    (root / "README.md").write_text("unexpected changed source", encoding="utf-8")
    result = _build_source(root, manifest=root / "BUNDLE-MANIFEST.json")
    assert result.returncode != 0
    assert "Source manifest content mismatch" in result.stderr
    assert previous.read_bytes() == b"previous release must remain unchanged"
    assert list(output.iterdir()) == [previous]


@pytest.mark.parametrize(
    "invalid_path",
    [
        "../outside.txt",
        "/outside.txt",
        "backend/../README.md",
        "backend\\secret.txt",
        "backend/.env",
        "diagnostics/private.txt",
    ],
)
def test_source_manifest_rejects_unsafe_or_excluded_paths(
    tmp_path: Path, invalid_path: str
) -> None:
    root = _source_tree(tmp_path, git=False)
    manifest = root / "BUNDLE-MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "release-bundle-manifest.v1",
                "file_count": 1,
                "files": [{"path": invalid_path, "size": 0, "sha256": "0" * 64}],
            }
        ),
        encoding="utf-8",
    )
    result = _build_source(root, manifest=manifest)
    assert result.returncode != 0
    assert "source path" in result.stderr or "excluded path" in result.stderr
    assert not list((root / "release-output").glob("*.zip"))
