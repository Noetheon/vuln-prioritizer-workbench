from __future__ import annotations

import copy
import tomllib

import pytest
from packaging.version import Version
from scripts.build_dependency_graph_snapshot import MANIFEST, build_snapshot
from utils.hygiene import REPO_ROOT


def _current_lock() -> dict:
    with (REPO_ROOT / "uv.lock").open("rb") as stream:
        return tomllib.load(stream)


def _snapshot(lock: dict) -> dict:
    return build_snapshot(
        lock,
        sha="0e5984de514b3c768a9536ecd3804d211e3be64e",
        ref="refs/heads/main",
        job_id="test",
        scanned="2026-09-23T00:00:00Z",
    )


def test_snapshot_represents_every_locked_dependency_with_correct_scope() -> None:
    lock = _current_lock()
    snapshot = _snapshot(lock)
    resolved = snapshot["manifests"][MANIFEST]["resolved"]
    package_names = {
        package["name"]
        for package in lock["package"]
        if package["name"]
        not in {"vuln-prioritizer-workbench", "vuln-prioritizer-workbench-workspace"}
    }

    assert len(resolved) == len(package_names)
    assert all(set(entry["dependencies"]).issubset(resolved) for entry in resolved.values())

    def entry(name: str) -> tuple[str, dict]:
        matches = [
            (purl, data) for purl, data in resolved.items() if purl.startswith(f"pkg:pypi/{name}@")
        ]
        assert len(matches) == 1
        return matches[0]

    assert entry("psycopg-binary")[1]["scope"] == "runtime"
    fixed = {
        "anyio": ("4.14.2", "runtime"),
        "soupsieve": ("2.9.0", "development"),
        "pip": ("26.2.0", "development"),
        "cryptography": ("50.0.0", "development"),
        "msgpack": ("1.2.1", "development"),
    }
    for name, (first_patched, scope) in fixed.items():
        purl, data = entry(name)
        assert Version(purl.rsplit("@", 1)[1]) >= Version(first_patched)
        assert data["scope"] == scope


def test_snapshot_fails_closed_when_lock_references_missing_package() -> None:
    lock = copy.deepcopy(_current_lock())
    lock["package"] = [package for package in lock["package"] if package["name"] != "anyio"]

    with pytest.raises(ValueError, match="missing referenced package 'anyio'"):
        _snapshot(lock)
