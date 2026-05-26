"""Validate tracked archive binary evidence against a public-safe manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "archive" / "vpw-evidence" / "BINARY-MANIFEST.json"
BINARY_SUFFIXES = {".gif", ".jpeg", ".jpg", ".png", ".webp", ".zip"}
TEXT_ZIP_SUFFIXES = {".csv", ".json", ".md", ".sarif", ".txt", ".xml", ".yml", ".yaml"}
FORBIDDEN_ZIP_NAME_TOKENS = (".env", "secret", "token", "cookie", "credential", "password")
PRIVATE_PATH_MARKERS = ("/Users/", "/private/", "/tmp/", "/var/folders/", "C:\\", "C:/")


@dataclass(frozen=True)
class BinaryEvidence:
    """Tracked binary archive evidence with its manifest metadata."""

    path: str
    kind: str
    size_bytes: int
    sha256: str


def main() -> int:
    """Validate or regenerate the archive binary evidence manifest."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--update",
        action="store_true",
        help="Rewrite the binary evidence manifest from tracked archive files.",
    )
    args = parser.parse_args()

    evidence = _tracked_binary_evidence()
    failures = _validate_binary_contents(evidence)
    if args.update:
        _write_manifest(evidence)
        print(f"{MANIFEST.relative_to(ROOT)} updated with {len(evidence)} binary entries.")
        return 0

    failures.extend(_validate_manifest(evidence))
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"archive binary evidence manifest: OK ({len(evidence)} tracked binary files)")
    return 0


def _tracked_binary_evidence() -> list[BinaryEvidence]:
    result = subprocess.run(
        ["git", "ls-files", "archive"],
        check=True,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        text=True,
    )
    entries: list[BinaryEvidence] = []
    for rel_path in sorted(line for line in result.stdout.splitlines() if line):
        path = ROOT / rel_path
        if not path.exists():
            continue
        suffix = path.suffix.lower()
        if suffix not in BINARY_SUFFIXES:
            continue
        entries.append(
            BinaryEvidence(
                path=rel_path,
                kind=suffix.removeprefix("."),
                size_bytes=path.stat().st_size,
                sha256=_sha256(path),
            )
        )
    return entries


def _validate_manifest(evidence: list[BinaryEvidence]) -> list[str]:
    if not MANIFEST.exists():
        return [f"{MANIFEST.relative_to(ROOT)} is missing; run with --update."]

    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failures: list[str] = []
    if payload.get("schema_version") != 1:
        failures.append("archive binary manifest schema_version must be 1.")
    if payload.get("root") != "archive/vpw-evidence":
        failures.append("archive binary manifest root must be archive/vpw-evidence.")

    actual = {entry.path: entry for entry in evidence}
    expected_entries = payload.get("files")
    if not isinstance(expected_entries, list):
        return [*failures, "archive binary manifest files must be a list."]
    expected = {
        str(entry.get("path")): entry for entry in expected_entries if isinstance(entry, dict)
    }

    missing = sorted(actual.keys() - expected.keys())
    extra = sorted(expected.keys() - actual.keys())
    if missing:
        failures.append("archive binary manifest is missing tracked files: " + ", ".join(missing))
    if extra:
        failures.append("archive binary manifest lists non-tracked files: " + ", ".join(extra))

    for rel_path, actual_entry in actual.items():
        expected_entry = expected.get(rel_path)
        if not expected_entry:
            continue
        if expected_entry.get("sha256") != actual_entry.sha256:
            failures.append(f"{rel_path}: sha256 drifted from archive binary manifest.")
        if expected_entry.get("size_bytes") != actual_entry.size_bytes:
            failures.append(f"{rel_path}: size drifted from archive binary manifest.")
        if expected_entry.get("kind") != actual_entry.kind:
            failures.append(f"{rel_path}: kind drifted from archive binary manifest.")
        purpose = str(expected_entry.get("purpose", "")).strip()
        if not purpose:
            failures.append(f"{rel_path}: purpose is required in archive binary manifest.")
    return failures


def _validate_binary_contents(evidence: list[BinaryEvidence]) -> list[str]:
    failures: list[str] = []
    for entry in evidence:
        if entry.kind == "zip":
            failures.extend(_validate_zip(ROOT / entry.path))
    return failures


def _validate_zip(path: Path) -> list[str]:
    failures: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            name = member.filename
            normalized = Path(name)
            if normalized.is_absolute() or ".." in normalized.parts:
                failures.append(f"{path.relative_to(ROOT)} contains unsafe ZIP member path: {name}")
            lower_name = name.lower()
            if any(token in lower_name for token in FORBIDDEN_ZIP_NAME_TOKENS):
                failures.append(
                    f"{path.relative_to(ROOT)} contains sensitive-looking member: {name}"
                )
            if Path(name).suffix.lower() in TEXT_ZIP_SUFFIXES:
                content = archive.read(member).decode("utf-8", errors="ignore")
                for marker in PRIVATE_PATH_MARKERS:
                    if marker in content:
                        failures.append(
                            f"{path.relative_to(ROOT)} member {name} contains private path marker "
                            f"{marker!r}."
                        )
    return failures


def _write_manifest(evidence: list[BinaryEvidence]) -> None:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "root": "archive/vpw-evidence",
        "policy": (
            "Historical binary evidence must be public-safe, purpose-labelled, "
            "and hash-pinned. ZIP members are checked for unsafe paths and "
            "sensitive-looking names."
        ),
        "files": [
            {
                "path": entry.path,
                "kind": entry.kind,
                "size_bytes": entry.size_bytes,
                "sha256": entry.sha256,
                "purpose": _default_purpose(entry.path),
            }
            for entry in evidence
        ],
    }
    MANIFEST.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _default_purpose(path: str) -> str:
    if "/final-demo-flow/" in path:
        return "Historical final demo flow screenshot."
    if path.endswith(".zip"):
        return "Historical evidence bundle artifact retained for verification context."
    return "Historical issue-level Workbench evidence screenshot."


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
