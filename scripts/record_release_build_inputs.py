"""Record and validate the locked Python tools used for release builds."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("build", "pip", "setuptools", "twine", "wheel")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}\Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _locked_versions() -> dict[str, str]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    versions: dict[str, str] = {}
    for package in lock["package"]:
        name = str(package["name"])
        if name not in TOOLS:
            continue
        if name in versions:
            raise ValueError(f"Ambiguous locked version for {name}")
        versions[name] = str(package["version"])
    if set(versions) != set(TOOLS):
        raise ValueError(f"Missing locked release tools: {sorted(set(TOOLS) - set(versions))}")
    return versions


def main() -> int:
    """Write a checked, machine-readable record for the current build environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--run-url", default=None)
    args = parser.parse_args()

    if COMMIT_RE.fullmatch(args.commit) is None:
        parser.error("--commit must be a full Git commit SHA")
    if not args.ref:
        parser.error("--ref must not be empty")

    try:
        locked = _locked_versions()
        installed = {name: importlib.metadata.version(name) for name in TOOLS}
        if installed != locked:
            raise ValueError(f"Release tools differ from uv.lock: {installed!r} != {locked!r}")
        uv_version = subprocess.check_output(["uv", "--version"], text=True).strip()
        payload = {
            "schema_version": "release-build-inputs.v1",
            "commit": args.commit,
            "ref": args.ref,
            "run_url": args.run_url,
            "python": platform.python_version(),
            "uv": uv_version,
            "locked_and_installed_tools": installed,
            "input_sha256": {
                "uv.lock": _sha256(ROOT / "uv.lock"),
                "backend/requirements.lock.txt": _sha256(ROOT / "backend/requirements.lock.txt"),
                "backend/pyproject.toml": _sha256(ROOT / "backend/pyproject.toml"),
                "frontend/package-lock.json": _sha256(ROOT / "frontend/package-lock.json"),
            },
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
