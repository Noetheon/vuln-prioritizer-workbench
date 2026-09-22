"""
Submit the resolved uv.lock graph, rather than guessed transitive versions.

The snapshot is associated with backend/pyproject.toml because that file owns
the package's runtime and dev requirements. uv.lock supplies the exact versions
and edges. Platform markers are intentionally unioned: a lock is a cross-platform
set of possible installations, not an observation from one runner.
"""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT_PACKAGE = "vuln-prioritizer-workbench"
MANIFEST = "backend/pyproject.toml"
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def _purl(package: dict[str, Any]) -> str:
    name = package["name"]
    version = package["version"]
    if not PACKAGE_NAME.fullmatch(name) or not version or "@" in version:
        raise ValueError(f"Invalid locked package identity: {name!r} {version!r}")
    return f"pkg:pypi/{name.replace('_', '-').lower()}@{version}"


def _walk(
    roots: list[dict[str, Any]], packages: dict[str, dict[str, Any]]
) -> tuple[set[str], dict[str, set[str]]]:
    visited: set[tuple[str, tuple[str, ...]]] = set()
    reached: set[str] = set()
    edges: dict[str, set[str]] = defaultdict(set)
    queue = deque(roots)
    while queue:
        reference = queue.popleft()
        name = reference["name"]
        extras = tuple(sorted(reference.get("extra", [])))
        if name not in packages:
            raise ValueError(f"uv.lock is missing referenced package {name!r}")
        if (name, extras) in visited:
            continue
        visited.add((name, extras))
        reached.add(name)
        package = packages[name]
        children = list(package.get("dependencies", []))
        for extra in extras:
            optional = package.get("optional-dependencies", {})
            if extra not in optional:
                raise ValueError(f"uv.lock is missing {name!r} extra {extra!r}")
            children.extend(optional[extra])
        for child in children:
            edges[name].add(child["name"])
            queue.append(child)
    return reached, edges


def build_snapshot(
    lock: dict[str, Any], *, sha: str, ref: str, job_id: str, scanned: str
) -> dict[str, Any]:
    """Build a complete, scoped GitHub submission from a universal uv lock."""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("A full 40-character commit SHA is required")
    if not ref.startswith("refs/heads/") or not job_id:
        raise ValueError("A branch ref and job ID are required")
    packages_list = lock["package"]
    packages = {package["name"]: package for package in packages_list}
    if len(packages) != len(packages_list):
        raise ValueError("uv.lock has multiple resolutions for the same package name")
    root = packages[ROOT_PACKAGE]
    if root["source"].get("editable") != "backend":
        raise ValueError("uv.lock does not identify the local backend package")
    runtime_roots = root["dependencies"]
    dev_roots = root["optional-dependencies"]["dev"]
    runtime, runtime_edges = _walk(runtime_roots, packages)
    dev, dev_edges = _walk(dev_roots, packages)
    reached = runtime | dev
    expected = set(packages) - {ROOT_PACKAGE, "vuln-prioritizer-workbench-workspace"}
    if reached != expected:
        raise ValueError(
            f"uv.lock graph is incomplete: missing={sorted(expected - reached)}, "
            f"unexpected={sorted(reached - expected)}"
        )
    direct = {item["name"] for item in runtime_roots + dev_roots}
    resolved = {}
    for name in sorted(reached):
        package = packages[name]
        if package["source"].get("registry") != "https://pypi.org/simple":
            raise ValueError(f"Unexpected source for dependency {name!r}")
        children = runtime_edges.get(name, set()) | dev_edges.get(name, set())
        resolved[_purl(package)] = {
            "package_url": _purl(package),
            "relationship": "direct" if name in direct else "indirect",
            "scope": "runtime" if name in runtime else "development",
            "dependencies": sorted(_purl(packages[child]) for child in children),
        }
    if not resolved or not runtime or not dev:
        raise ValueError("Resolved graph unexpectedly has an empty scope")
    return {
        "version": 0,
        "sha": sha,
        "ref": ref,
        "job": {"id": job_id, "correlator": "vpw-uv-lock-backend"},
        "detector": {
            "name": "vpw-uv-lock",
            "version": "1",
            "url": "https://github.com/Noetheon/vuln-prioritizer-workbench",
        },
        "scanned": scanned,
        "manifests": {
            MANIFEST: {
                "name": MANIFEST,
                "file": {"source_location": MANIFEST},
                "metadata": {"resolved_from": "uv.lock", "scope": "supported-platform-union"},
                "resolved": resolved,
            }
        },
    }


def main() -> None:
    """Write a snapshot for a checked-out GitHub Actions commit."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.lock.open("rb") as stream:
        lock = tomllib.load(stream)
    scanned = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    snapshot = build_snapshot(lock, sha=args.sha, ref=args.ref, job_id=args.job_id, scanned=scanned)
    args.output.write_text(json.dumps(snapshot, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"Snapshot contains {len(snapshot['manifests'][MANIFEST]['resolved'])} "
        "resolved Python dependencies."
    )


if __name__ == "__main__":
    main()
