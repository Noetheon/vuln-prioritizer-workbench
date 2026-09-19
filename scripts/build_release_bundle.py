"""Build an end-user local Workbench release ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import tomllib
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

REPO_ROOT = Path(__file__).resolve().parents[1]

INCLUDE_ROOT_FILES = {
    ".env.example",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "INSTALL.md",
    "LICENSE",
    "MAINTAINERS.md",
    "Makefile",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "SUPPORT.md",
    "TROUBLESHOOTING.md",
    "compose.override.yml",
    "compose.production-smoke.yml",
    "compose.traefik.yml",
    "compose.yml",
    "launch-workbench.bat",
    "launch-workbench.command",
    "mkdocs.yml",
    "package.json",
    "pyproject.toml",
    "uv.lock",
}
INCLUDE_ROOT_DIRS = {
    ".github/workflows",
    "backend",
    "data",
    "docs",
    "examples",
    "frontend",
    "scripts",
}
EXCLUDED_PARTS = {
    ".cache",
    ".git",
    ".hypothesis",
    ".mypy_cache",
    ".playwright-cli",
    ".playwright-mcp",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "output",
    "outputs",
    "site",
    "test-results",
}
EXCLUDED_PREFIXES = {
    "archive",
    "data/provider-snapshots",
    "data/uploads",
    "data/workbench-import-uploads",
    "data/workbench-provider-cache",
    "data/workbench-reports",
    "diagnostics",
    "frontend/blob-report",
    "frontend/dist",
    "frontend/node_modules",
    "frontend/playwright-report",
    "frontend/test-results",
}
EXCLUDED_SUFFIXES = {
    ".db",
    ".log",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
}


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default="dist",
        help="Directory where the ZIP, manifest copy, and SHA-256 file are written.",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Override the bundle version. Defaults to backend/pyproject.toml.",
    )
    parser.add_argument(
        "--source-manifest",
        type=Path,
        help=(
            "For an extracted source bundle without Git: verify and package only files "
            "in this BUNDLE-MANIFEST.json."
        ),
    )
    args = parser.parse_args()

    version = args.version or _package_version()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", version) is None:
        parser.error("Bundle version must be a filename-safe version without path separators.")
    output_dir = (REPO_ROOT / args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = f"vuln-prioritizer-workbench-local-{version}"
    zip_path = output_dir / f"{bundle_name}.zip"
    manifest_copy_path = output_dir / f"{bundle_name}-manifest.json"
    sha256_path = output_dir / f"{bundle_name}.zip.sha256"

    try:
        source_manifest = _load_source_manifest(args.source_manifest)
        files = _bundle_files(source_manifest=source_manifest)
        manifest = _write_bundle(
            zip_path,
            bundle_name=bundle_name,
            version=version,
            files=files,
            source_manifest=source_manifest,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))

    zip_hash = _sha256_file(zip_path)
    manifest_copy_path.write_text(
        json.dumps({**manifest, "bundle_sha256": zip_hash}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sha256_path.write_text(f"{zip_hash}  {zip_path.name}\n", encoding="utf-8")
    print(zip_path)
    return 0


def _package_version() -> str:
    pyproject = tomllib.loads((REPO_ROOT / "backend" / "pyproject.toml").read_text())
    return str(pyproject["project"]["version"])


def _bundle_files(*, source_manifest: dict[str, object] | None = None) -> list[Path]:
    """Select explicit source inputs; never enumerate the working directory."""
    if source_manifest is not None:
        candidates = [Path(item["path"]) for item in source_manifest["files"]]
    else:
        try:
            tracked = subprocess.check_output(
                ["git", "ls-files", "--cached", "--stage", "-z"],
                cwd=REPO_ROOT,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ValueError(
                "Release inputs require a Git index or an explicit --source-manifest."
            ) from exc
        candidates = []
        for entry in tracked.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.decode("utf-8").split("\t", maxsplit=1)
            mode, _object_id, stage = metadata.split()
            relative_path = _safe_relative_path(raw_path)
            if not _included(relative_path) or _excluded(relative_path):
                continue
            if stage != "0" or mode not in {"100644", "100755"}:
                raise ValueError(f"Release source must be a resolved regular file: {raw_path}")
            candidates.append(relative_path)
    files = sorted(set(candidates))
    if not files:
        raise ValueError("No allowed release source files were found.")
    for relative_path in files:
        _validate_source_file(relative_path)
    return files


def _safe_relative_path(value: str) -> Path:
    if (
        not value
        or "\\" in value
        or "\0" in value
        or ":" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or Path(value).is_absolute()
    ):
        raise ValueError(f"Invalid release source path: {value!r}")
    return Path(value)


def _validate_source_file(relative_path: Path) -> Path:
    source = REPO_ROOT / relative_path
    candidate = REPO_ROOT
    for part in relative_path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError(f"Release source cannot follow symlinks: {relative_path}")
    if not stat.S_ISREG(source.stat().st_mode):
        raise ValueError(f"Release source is not a regular file: {relative_path}")
    return source


@contextmanager
def _open_source_file(relative_path: Path) -> Iterator[BinaryIO]:
    """Open an indexed source without traversing symlinked parent directories."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
        parent = os.open(REPO_ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in relative_path.parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            descriptor = os.open(relative_path.name, flags, dir_fd=parent)
        finally:
            os.close(parent)
    else:
        descriptor = os.open(_validate_source_file(relative_path), flags)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError(f"Release source is not a regular file: {relative_path}")
        yield handle


def _load_source_manifest(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != "release-bundle-manifest.v1"
    ):
        raise ValueError("Source manifest must use release-bundle-manifest.v1.")
    entries = payload.get("files")
    if (
        not isinstance(entries, list)
        or type(payload.get("file_count")) is not int
        or payload["file_count"] != len(entries)
    ):
        raise ValueError("Source manifest file count does not match its file list.")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("Source manifest entries require a path, size and SHA-256.")
        relative_path = _safe_relative_path(entry["path"])
        if not _included(relative_path) or _excluded(relative_path):
            raise ValueError(f"Source manifest contains an excluded path: {relative_path}")
        if entry["path"] in seen:
            raise ValueError(f"Source manifest contains duplicate path: {relative_path}")
        seen.add(entry["path"])
        if (
            type(entry.get("size")) is not int
            or entry["size"] < 0
            or not isinstance(entry.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
        ):
            raise ValueError(f"Source manifest has invalid size or SHA-256: {relative_path}")
    commit = payload.get("commit")
    if commit is not None and (
        not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None
    ):
        raise ValueError("Source manifest has an invalid Git commit.")
    return payload


def _included(relative_path: Path) -> bool:
    normalized = relative_path.as_posix()
    if normalized in INCLUDE_ROOT_FILES:
        return True
    return any(
        normalized == root or normalized.startswith(f"{root}/") for root in INCLUDE_ROOT_DIRS
    )


def _excluded(relative_path: Path) -> bool:
    normalized = relative_path.as_posix()
    if relative_path.name == ".DS_Store":
        return True
    if (
        relative_path.name == ".env" or relative_path.name.startswith(".env.")
    ) and relative_path.name != ".env.example":
        return True
    if relative_path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    if any(part in EXCLUDED_PARTS for part in relative_path.parts):
        return True
    if any(
        normalized == prefix or normalized.startswith(f"{prefix}/") for prefix in EXCLUDED_PREFIXES
    ):
        return True
    if normalized.startswith("data/provider-snapshot-"):
        return True
    return False


def _write_bundle(
    zip_path: Path,
    *,
    bundle_name: str,
    version: str,
    files: list[Path],
    source_manifest: dict[str, object] | None,
) -> dict[str, object]:
    """Hash the exact archived bytes and publish only after source verification."""
    expected = (
        {item["path"]: item for item in source_manifest["files"]}
        if source_manifest is not None
        else {}
    )
    manifest: dict[str, object] = {
        "schema_version": "release-bundle-manifest.v1",
        "bundle_name": bundle_name,
        "version": version,
        "commit": source_manifest.get("commit") if source_manifest is not None else _git_commit(),
        "source_selection": "verified_manifest" if source_manifest is not None else "git_index",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "file_count": len(files),
        "files": [],
    }
    with tempfile.NamedTemporaryFile(dir=zip_path.parent, suffix=".zip", delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for relative_path in files:
                digest = hashlib.sha256()
                size = 0
                with _open_source_file(relative_path) as handle:
                    info = zipfile.ZipInfo(f"{bundle_name}/{relative_path.as_posix()}")
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = os.fstat(handle.fileno()).st_mode << 16
                    with archive.open(info, "w") as target:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            target.write(chunk)
                            digest.update(chunk)
                            size += len(chunk)
                entry = {
                    "path": relative_path.as_posix(),
                    "size": size,
                    "sha256": digest.hexdigest(),
                }
                if expected and any(entry[key] != expected[entry["path"]][key] for key in entry):
                    raise ValueError(f"Source manifest content mismatch: {relative_path}")
                manifest["files"].append(entry)
            archive.writestr(
                f"{bundle_name}/BUNDLE-MANIFEST.json",
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            )
        temporary_path.replace(zip_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return manifest


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
