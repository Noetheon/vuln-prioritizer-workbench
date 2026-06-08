"""Build an end-user local Workbench release ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path

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
    args = parser.parse_args()

    version = args.version or _package_version()
    output_dir = (REPO_ROOT / args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = f"vuln-prioritizer-workbench-local-{version}"
    zip_path = output_dir / f"{bundle_name}.zip"
    manifest_copy_path = output_dir / f"{bundle_name}-manifest.json"
    sha256_path = output_dir / f"{bundle_name}.zip.sha256"

    files = _bundle_files()
    manifest = _manifest(
        bundle_name=bundle_name,
        version=version,
        files=files,
    )

    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path in files:
            archive.write(
                REPO_ROOT / relative_path,
                f"{bundle_name}/{relative_path.as_posix()}",
            )
        archive.writestr(
            f"{bundle_name}/BUNDLE-MANIFEST.json",
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        )

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


def _bundle_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(REPO_ROOT)
        if _included(relative_path) and not _excluded(relative_path):
            files.append(relative_path)
    return files


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


def _manifest(
    *,
    bundle_name: str,
    version: str,
    files: list[Path],
) -> dict[str, object]:
    return {
        "schema_version": "release-bundle-manifest.v1",
        "bundle_name": bundle_name,
        "version": version,
        "commit": _git_commit(),
        "created_at_utc": datetime.now(UTC).isoformat(),
        "file_count": len(files),
        "files": [
            {
                "path": relative_path.as_posix(),
                "size": (REPO_ROOT / relative_path).stat().st_size,
                "sha256": _sha256_file(REPO_ROOT / relative_path),
            }
            for relative_path in files
        ],
    }


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
