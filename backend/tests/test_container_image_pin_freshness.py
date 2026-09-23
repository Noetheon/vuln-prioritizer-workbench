"""Focused tests for the scheduled container tag/digest review."""

from __future__ import annotations

import hashlib
import subprocess
from types import SimpleNamespace

from scripts import check_container_image_pin_freshness as freshness


def test_current_digest_hashes_registry_manifest_without_reformatting(monkeypatch):
    manifest = b'{"schemaVersion":2,"manifests":[]}'

    def fake_run(command, **kwargs):
        assert command == ["docker", "buildx", "imagetools", "inspect", "--raw", "example:1"]
        assert kwargs == {"check": True, "capture_output": True}
        return SimpleNamespace(stdout=manifest)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert freshness.current_digest("example:1") == hashlib.sha256(manifest).hexdigest()


def test_pin_review_reports_same_tag_digest_drift(tmp_path, monkeypatch, capsys):
    dockerfile = tmp_path / "Dockerfile"
    old_digest = "a" * 64
    new_digest = "b" * 64
    dockerfile.write_text(f"FROM example:1@sha256:{old_digest}\n", encoding="utf-8")
    monkeypatch.setattr(freshness, "ROOT", tmp_path)
    monkeypatch.setattr(freshness, "IMAGE_FILES", (dockerfile,))
    monkeypatch.setattr(freshness, "current_digest", lambda _tag: new_digest)

    assert freshness.main() == 1
    assert f"Dockerfile:1: example:1 now resolves to sha256:{new_digest}" in capsys.readouterr().err


def test_pin_review_accepts_matching_digest_and_skips_dynamic_images(tmp_path, monkeypatch, capsys):
    dockerfile = tmp_path / "Dockerfile"
    digest = "c" * 64
    dockerfile.write_text(f"FROM example:1@sha256:{digest}\nimage: ${{IMAGE}}\n", encoding="utf-8")
    monkeypatch.setattr(freshness, "ROOT", tmp_path)
    monkeypatch.setattr(freshness, "IMAGE_FILES", (dockerfile,))
    monkeypatch.setattr(freshness, "current_digest", lambda _tag: digest)

    assert freshness.main() == 0
    assert "1 references match" in capsys.readouterr().out
