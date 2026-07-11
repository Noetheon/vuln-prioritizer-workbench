"""Synchronize packaged frontend and demo resources for ``vpw serve``."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIST = ROOT / "frontend" / "dist"
PACKAGE_ROOT = ROOT / "backend" / "app"
STATIC_TARGET = PACKAGE_ROOT / "static"
RESOURCE_TARGET = PACKAGE_ROOT / "resources"
MANIFEST_NAME = "RUNTIME-ASSETS.json"

RESOURCE_FILES = (
    Path("data/demo_provider_snapshot.json"),
    Path("data/attack/attack_stix_enterprise_16.1_subset.json"),
    Path("data/attack/attack_techniques_enterprise_16.1_subset.json"),
    Path("data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
    Path("data/attack/local_curated_demo_mappings.yml"),
    Path("data/input_fixtures/demo_workspace_occurrences.csv"),
    Path("data/input_fixtures/demo_workspace_occurrences_history_01.csv"),
    Path("data/input_fixtures/demo_workspace_occurrences_history_02.csv"),
    Path("data/input_fixtures/demo_workspace_occurrences_history_03.csv"),
    Path("data/input_fixtures/demo_workspace_occurrences_history_04.csv"),
    Path("data/input_fixtures/demo_workspace_occurrences_history_05.csv"),
    Path("data/input_fixtures/demo_workspace_occurrences_history_06.csv"),
    Path("data/input_fixtures/demo_workspace_openvex.json"),
    Path("data/input_fixtures/example_asset_context.csv"),
)


def main() -> int:
    """Synchronize assets or verify that the committed package copy is current."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    _require_sources()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="vpw-runtime-assets-") as raw_temp:
            expected_root = Path(raw_temp)
            _build_targets(expected_root / "static", expected_root / "resources")
            mismatches = _tree_mismatches(expected_root / "static", STATIC_TARGET)
            mismatches.extend(_tree_mismatches(expected_root / "resources", RESOURCE_TARGET))
        if mismatches:
            detail = "\n".join(f"- {item}" for item in mismatches[:30])
            raise SystemExit(
                "Packaged runtime assets are stale. Run 'make runtime-assets-sync'.\n" + detail
            )
        print("Packaged runtime assets match the frontend build and runtime resources.")
        return 0

    _replace_directory(STATIC_TARGET)
    _replace_directory(RESOURCE_TARGET)
    _build_targets(STATIC_TARGET, RESOURCE_TARGET)
    print(f"Synchronized packaged runtime assets under {PACKAGE_ROOT}.")
    return 0


def _require_sources() -> None:
    if not (FRONTEND_DIST / "index.html").is_file():
        raise SystemExit("frontend/dist is missing; run the pinned frontend build first.")
    missing = [str(path) for path in RESOURCE_FILES if not (ROOT / path).is_file()]
    if missing:
        raise SystemExit(f"Required runtime resources are missing: {', '.join(missing)}")


def _build_targets(static_target: Path, resource_target: Path) -> None:
    shutil.copytree(FRONTEND_DIST, static_target, dirs_exist_ok=True)
    for relative in RESOURCE_FILES:
        source = ROOT / relative
        destination_relative = relative.relative_to("data")
        destination = resource_target / destination_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    _write_manifest(static_target, resource_target)


def _write_manifest(static_target: Path, resource_target: Path) -> None:
    entries: dict[str, str] = {}
    for label, root in (("static", static_target), ("resources", resource_target)):
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.name != MANIFEST_NAME:
                entries[f"{label}/{path.relative_to(root).as_posix()}"] = _sha256(path)
    payload = {"schema_version": "vpw-runtime-assets.v1", "files": entries}
    (resource_target / MANIFEST_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _replace_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def _tree_mismatches(expected: Path, actual: Path) -> list[str]:
    expected_files = {
        path.relative_to(expected).as_posix(): _sha256(path)
        for path in expected.rglob("*")
        if path.is_file()
    }
    actual_files = (
        {
            path.relative_to(actual).as_posix(): _sha256(path)
            for path in actual.rglob("*")
            if path.is_file()
        }
        if actual.is_dir()
        else {}
    )
    mismatches = []
    for relative in sorted(expected_files.keys() | actual_files.keys()):
        if expected_files.get(relative) != actual_files.get(relative):
            mismatches.append(relative)
    return mismatches


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
