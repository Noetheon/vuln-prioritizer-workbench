"""End-to-end checks for archive-bound release SBOMs and evidence verification."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from paths import REPO_ROOT

VERSION = "1.3.0"
COMMIT = "a" * 40
SCRIPT = REPO_ROOT / "scripts" / "build_release_artifact_evidence.py"
RUN_URL = "https://github.com/Noetheon/vuln-prioritizer-workbench/actions/runs/123"
RELEASE_TOOLS = {
    "build": "1.3.0",
    "pip": "26.0",
    "setuptools": "84.0.0",
    "twine": "6.2.0",
    "wheel": "0.48.0",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fixtures(
    dist: Path,
    *,
    unsafe_wheel_path: str | None = None,
    tampered_bundle_file: bool = False,
) -> None:
    dist.mkdir()
    metadata = (
        b"Metadata-Version: 2.3\n"
        b"Name: vuln-prioritizer-workbench\n"
        b"Version: 1.3.0\n"
        b"Requires-Dist: anyio>=4.14.2,<5.0\n"
        b'Requires-Dist: pytest>=8; extra == "dev"\n'
    )
    wheel = dist / f"vuln_prioritizer_workbench-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("app/__init__.py", b"release example\n")
        archive.writestr(f"vuln_prioritizer_workbench-{VERSION}.dist-info/METADATA", metadata)
        if unsafe_wheel_path:
            archive.writestr(unsafe_wheel_path, b"unexpected")

    sdist = dist / f"vuln_prioritizer_workbench-{VERSION}.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, content in (
            (f"vuln_prioritizer_workbench-{VERSION}/PKG-INFO", metadata),
            (f"vuln_prioritizer_workbench-{VERSION}/app/__init__.py", b"release example\n"),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))

    prefix = f"vuln-prioritizer-workbench-local-{VERSION}/"
    files = {
        "README.md": b"Local Workbench source bundle.\n",
        "backend/pyproject.toml": (
            b"[project]\nname = 'vuln-prioritizer-workbench'\nversion = '1.3.0'\n"
        ),
        "uv.lock": (
            b"version = 1\n"
            b"[[package]]\nname = 'anyio'\nversion = '4.15.1'\n"
            b"source = { registry = 'https://pypi.org/simple' }\n"
            b"[[package]]\nname = 'vuln-prioritizer-workbench'\nversion = '1.3.0'\n"
            b"source = { editable = 'backend' }\n"
            + b"".join(
                (
                    f"[[package]]\nname = '{name}'\nversion = '{version}'\n"
                    "source = { registry = 'https://pypi.org/simple' }\n"
                ).encode()
                for name, version in RELEASE_TOOLS.items()
            )
        ),
        "backend/requirements.lock.txt": b"# Pinned release build constraints.\n",
        "frontend/package-lock.json": json.dumps(
            {
                "packages": {
                    "": {"name": "frontend", "version": "1.0.0"},
                    "node_modules/react": {"version": "19.3.0"},
                    "node_modules/@types/react": {"version": "19.3.0", "dev": True},
                }
            }
        ).encode(),
    }
    manifest = {
        "schema_version": "release-bundle-manifest.v1",
        "version": VERSION,
        "commit": COMMIT,
        "file_count": len(files),
        "files": [
            {"path": name, "size": len(data), "sha256": _sha256(data)}
            for name, data in sorted(files.items())
        ],
    }
    bundle = dist / f"vuln-prioritizer-workbench-local-{VERSION}.zip"
    if tampered_bundle_file:
        files["README.md"] = b"Changed after manifest hashing.\n"
    with zipfile.ZipFile(bundle, "w") as archive:
        for name, data in files.items():
            archive.writestr(prefix + name, data)
        archive.writestr(prefix + "BUNDLE-MANIFEST.json", json.dumps(manifest))


def _build_inputs(dist: Path, *, commit: str = COMMIT, ref: str = "refs/tags/v1.3.0") -> bytes:
    bundle = dist / f"vuln-prioritizer-workbench-local-{VERSION}.zip"
    paths = (
        "uv.lock",
        "backend/requirements.lock.txt",
        "backend/pyproject.toml",
        "frontend/package-lock.json",
    )
    with zipfile.ZipFile(bundle) as archive:
        hashes = {
            path: _sha256(archive.read(f"vuln-prioritizer-workbench-local-{VERSION}/{path}"))
            for path in paths
        }
    return (
        json.dumps(
            {
                "schema_version": "release-build-inputs.v1",
                "commit": commit,
                "ref": ref,
                "run_url": RUN_URL,
                "python": "3.14.0",
                "uv": "uv 0.11.31",
                "locked_and_installed_tools": RELEASE_TOOLS,
                "input_sha256": hashes,
            }
        )
        + "\n"
    ).encode()


def _run(dist: Path, output: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--dist",
            str(dist),
            "--output",
            str(output),
            *extra,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_release_artifact_evidence_is_deterministic_and_verifies_archive_bytes(
    tmp_path: Path,
) -> None:
    dist = tmp_path / "dist"
    _fixtures(dist)
    inputs = tmp_path / "inputs.json"
    inputs.write_bytes(_build_inputs(dist))
    first = tmp_path / "evidence-1"
    second = tmp_path / "evidence-2"
    options = (
        "--commit",
        COMMIT,
        "--created",
        "2026-09-23T12:00:00Z",
        "--ref",
        "refs/tags/v1.3.0",
        "--run-url",
        RUN_URL,
        "--build-inputs",
        str(inputs),
    )
    assert _run(dist, first, *options).returncode == 0
    assert _run(dist, second, *options).returncode == 0
    assert {p.name: p.read_bytes() for p in first.iterdir()} == {
        p.name: p.read_bytes() for p in second.iterdir()
    }
    assert _run(dist, first, "--verify").returncode == 0

    index = json.loads((first / "release-artifact-evidence.json").read_text())
    assert [subject["kind"] for subject in index["subjects"]] == [
        "wheel",
        "sdist",
        "local_source_zip",
    ]
    assert index["build"]["inputs"]["sha256"] == _sha256(inputs.read_bytes())
    for subject in index["subjects"]:
        artifact = dist / subject["name"]
        sbom = json.loads((first / subject["sbom"]).read_text())
        assert subject["sha256"] == _sha256(artifact.read_bytes())
        assert sbom["packages"][0]["checksums"][0]["checksumValue"] == subject["sha256"]
        assert len(sbom["files"]) == subject["archive_file_count"]
        assert len(sbom["packages"]) == subject["dependency_reference_count"] + 1

    wheel_sbom = json.loads(
        (first / f"vuln_prioritizer_workbench-{VERSION}-py3-none-any.whl.spdx.json").read_text()
    )
    assert {package["name"] for package in wheel_sbom["packages"][1:]} == {
        "anyio",
        "pytest",
    }
    assert {json.loads(item["comment"])["requirement"] for item in wheel_sbom["packages"][1:]} == {
        "anyio>=4.14.2,<5.0",
        'pytest>=8; extra == "dev"',
    }
    assert all(item["filesAnalyzed"] is False for item in wheel_sbom["packages"][1:])
    assert all(
        relation["relationshipType"] == "DEPENDS_ON"
        for relation in wheel_sbom["relationships"]
        if relation["relatedSpdxElement"].startswith("SPDXRef-Dependency")
    )
    bundle_sbom = json.loads(
        (first / f"vuln-prioritizer-workbench-local-{VERSION}.zip.spdx.json").read_text()
    )
    assert {package["name"] for package in bundle_sbom["packages"][1:]} == {
        "anyio",
        "vuln-prioritizer-workbench",
        "react",
        "@types/react",
        *RELEASE_TOOLS,
    }
    editable = next(
        item for item in bundle_sbom["packages"][1:] if item["name"] == "vuln-prioritizer-workbench"
    )
    assert "externalRefs" not in editable
    assert all(
        relation["relationshipType"] == "OTHER"
        for relation in bundle_sbom["relationships"]
        if relation["relatedSpdxElement"].startswith("SPDXRef-Dependency")
    )


def test_verify_rejects_modified_release_artifact_and_sbom(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _fixtures(dist)
    output = tmp_path / "evidence"
    assert (
        _run(dist, output, "--commit", COMMIT, "--created", "2026-09-23T12:00:00Z").returncode == 0
    )
    wheel = dist / f"vuln_prioritizer_workbench-{VERSION}-py3-none-any.whl"
    with wheel.open("ab") as handle:
        handle.write(b"altered after evidence generation")
    assert "Artifact evidence mismatch" in _run(dist, output, "--verify").stderr
    wheel.write_bytes(wheel.read_bytes().removesuffix(b"altered after evidence generation"))
    sbom = output / f"{wheel.name}.spdx.json"
    sbom.write_text("{}")
    assert "SPDX inventory mismatch" in _run(dist, output, "--verify").stderr


def test_verify_rejects_modified_build_inputs(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _fixtures(dist)
    inputs = tmp_path / "inputs.json"
    inputs.write_bytes(_build_inputs(dist))
    output = tmp_path / "evidence"
    result = _run(
        dist,
        output,
        "--commit",
        COMMIT,
        "--created",
        "2026-09-23T12:00:00Z",
        "--ref",
        "refs/tags/v1.3.0",
        "--run-url",
        RUN_URL,
        "--build-inputs",
        str(inputs),
    )
    assert result.returncode == 0, result.stderr
    (output / "build-inputs.json").write_text('{"python":"different"}\n')
    assert "Build-inputs checksum mismatch" in _run(dist, output, "--verify").stderr


def test_build_rejects_build_inputs_not_matching_shipped_lock(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _fixtures(dist)
    payload = json.loads(_build_inputs(dist))
    payload["input_sha256"]["backend/requirements.lock.txt"] = "0" * 64
    inputs = tmp_path / "inputs.json"
    inputs.write_text(json.dumps(payload))
    output = tmp_path / "evidence"
    result = _run(
        dist,
        output,
        "--commit",
        COMMIT,
        "--ref",
        "refs/tags/v1.3.0",
        "--run-url",
        RUN_URL,
        "--build-inputs",
        str(inputs),
    )
    assert "Build-inputs checksum differs from source bundle" in result.stderr
    assert not output.exists()


def test_verify_rejects_rehashed_build_inputs_with_wrong_source_ref(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _fixtures(dist)
    inputs = tmp_path / "inputs.json"
    inputs.write_bytes(_build_inputs(dist))
    output = tmp_path / "evidence"
    assert (
        _run(
            dist,
            output,
            "--commit",
            COMMIT,
            "--ref",
            "refs/tags/v1.3.0",
            "--run-url",
            RUN_URL,
            "--build-inputs",
            str(inputs),
        ).returncode
        == 0
    )
    changed = json.loads((output / "build-inputs.json").read_text())
    changed["ref"] = "refs/heads/unreviewed"
    changed_bytes = (json.dumps(changed) + "\n").encode()
    (output / "build-inputs.json").write_bytes(changed_bytes)
    index_path = output / "release-artifact-evidence.json"
    index = json.loads(index_path.read_text())
    index["build"]["inputs"]["sha256"] = _sha256(changed_bytes)
    index_path.write_text(json.dumps(index) + "\n")
    assert (
        "Build-inputs source or workflow context mismatch" in _run(dist, output, "--verify").stderr
    )


def test_build_rejects_unsafe_archive_member(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _fixtures(dist, unsafe_wheel_path="../outside.txt")
    output = tmp_path / "evidence"
    result = _run(dist, output, "--commit", COMMIT, "--created", "2026-09-23T12:00:00Z")
    assert result.returncode != 0
    assert "Unsafe archive path" in result.stderr
    assert not (output / "release-artifact-evidence.json").exists()


def test_build_rejects_bundle_content_outside_its_manifest(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _fixtures(dist, tampered_bundle_file=True)
    output = tmp_path / "evidence"
    result = _run(dist, output, "--commit", COMMIT, "--created", "2026-09-23T12:00:00Z")
    assert result.returncode != 0
    assert "Bundle manifest file checksum/size mismatch" in result.stderr
    assert not (output / "release-artifact-evidence.json").exists()
