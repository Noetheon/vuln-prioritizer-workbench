from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from scripts import run_grype_integration as runner


def test_scanner_pin_matches_the_maintained_docker_version():
    pin = runner.scanner_pin()
    assert pin["version"]
    assert all(len(value) == 64 for value in pin["archives"].values())


def test_scanner_pin_drift_requires_review(tmp_path: Path, monkeypatch):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "docker/security-tools").mkdir(parents=True)
    (tmp_path / "scripts/grype-checksums.json").write_text(json.dumps({"version": "1.0.0"}))
    (tmp_path / "docker/security-tools/Dockerfile").write_text(
        "FROM anchore/grype:v2.0.0@sha256:" + "a" * 64
    )
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="Review native Grype checksums"):
        runner.scanner_pin()


@pytest.mark.parametrize("defect", [None, "checksum", "symlink"])
def test_scanner_download_verifies_before_publishing_an_executable(
    tmp_path: Path, monkeypatch, defect
):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w:gz") as bundle:
        member = tarfile.TarInfo("grype")
        if defect == "symlink":
            member.type, member.linkname = tarfile.SYMTYPE, "/tmp/untrusted-executable"
            bundle.addfile(member)
        else:
            member.size = 4
            bundle.addfile(member, io.BytesIO(b"test"))
    archive = content.getvalue()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def raise_for_status(self):
            pass

        def iter_content(self, _):
            yield archive

    monkeypatch.setattr(runner.requests, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner.platform, "machine", lambda: "x86_64")
    expected = "a" * 64 if defect == "checksum" else hashlib.sha256(archive).hexdigest()
    pin = {"version": "1.0.0", "archives": {"linux_amd64": expected}}
    if defect:
        with pytest.raises(ValueError, match="checksum mismatch|regular executable"):
            runner.download_binary(tmp_path, pin)
        assert not (tmp_path / "grype").exists()
    else:
        binary = runner.download_binary(tmp_path, pin)
        assert binary.read_bytes() == b"test"
        assert binary.stat().st_mode & 0o777 == 0o700
