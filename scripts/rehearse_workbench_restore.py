"""
Exercise a private SQLite Workbench backup and isolated restore.

The source runtime should be stopped while this runs. The temporary backup and
restored data are removed afterwards; only a private, content-free JSON summary
is retained under ignored build output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
ARTIFACT_ROOTS = ("imports", "reports", "provider-cache", "provider-snapshots")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _files(root: Path) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for name in ARTIFACT_ROOTS:
        directory = root / name
        if not directory.exists():
            continue
        if directory.is_symlink() and name in {"provider-cache", "provider-snapshots"}:
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("An artifact root is not a regular directory.")
        for candidate in directory.rglob("*"):
            if candidate.is_symlink():
                if name in {"provider-cache", "provider-snapshots"}:
                    continue
                raise ValueError("An upload or report tree contains a symlink.")
            if candidate.is_file():
                result[str(candidate.relative_to(root))] = (
                    candidate.stat().st_size,
                    _hash(candidate),
                )
    return result


def _database_state(database: Path, root: Path) -> dict[str, int]:
    root = root.resolve(strict=True)
    uri = f"{database.resolve(strict=True).as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("Restored SQLite integrity check failed.")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("Restored SQLite foreign key check failed.")
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        result = {
            "tables": len(tables),
            "projects": _count(connection, tables, "project"),
            "analysis_runs": _count(connection, tables, "analysis_run"),
            "decision_evidence": _count(connection, tables, "finding_decision_evidence"),
            "current_projections": _count(connection, tables, "finding_current_projection"),
            "reports_verified": 0,
            "uploads_verified": 0,
        }
        if "report" in tables:
            for path, size, digest in connection.execute(
                "SELECT path, size_bytes, sha256 FROM report"
            ):
                artifact = Path(path)
                if not artifact.is_file() or not artifact.resolve().is_relative_to(
                    root / "reports"
                ):
                    raise ValueError("Restored report path is missing or outside its root.")
                if artifact.stat().st_size != size or _hash(artifact) != digest:
                    raise ValueError("Restored report metadata does not match its file.")
                result["reports_verified"] += 1
        if "analysis_evidence" in tables:
            for (raw,) in connection.execute("SELECT payload_json FROM analysis_evidence"):
                payload = json.loads(raw) if isinstance(raw, str) else raw
                if not isinstance(payload, dict):
                    raise ValueError("Analysis evidence is not a JSON object.")
                uploads = payload.get("uploads") or {}
                if not isinstance(uploads, dict):
                    raise ValueError("Analysis evidence uploads are malformed.")
                for item in uploads.values():
                    if not isinstance(item, dict):
                        continue
                    reference = item.get("storage_ref") or item.get("path")
                    if not reference:
                        continue
                    relative = Path(reference)
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError("Managed upload has an unsafe reference.")
                    artifact = (root / "imports" / relative).resolve(strict=False)
                    if not artifact.is_file() or not artifact.is_relative_to(root / "imports"):
                        raise ValueError("Restored managed upload is missing or outside its root.")
                    size = item.get("size_bytes")
                    digest = item.get("sha256")
                    if isinstance(size, bool) or not isinstance(size, int):
                        raise ValueError("Managed upload has no verifiable size metadata.")
                    if not isinstance(digest, str) or len(digest) != 64:
                        raise ValueError("Managed upload has no verifiable SHA-256 metadata.")
                    if artifact.stat().st_size != size:
                        raise ValueError("Restored managed upload size differs from metadata.")
                    if _hash(artifact) != digest:
                        raise ValueError("Restored managed upload hash differs from metadata.")
                    result["uploads_verified"] += 1
        return result


def _count(connection: sqlite3.Connection, tables: set[str], table: str) -> int:
    return (
        int(connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
        if table in tables
        else 0
    )


def _run(command: list[str], *, environment: dict[str, str]) -> None:
    result = subprocess.run(command, env=environment, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{Path(command[0]).name} exited with status {result.returncode}.")


def main() -> int:
    """Run a private isolated recovery exercise and record a content-free result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--evidence-dir", type=Path, default=Path("build/recovery-rehearsals"))
    parser.add_argument(
        "--source-kind", choices=("operator", "synthetic", "unclassified"), default="unclassified"
    )
    parser.add_argument("--vpw", type=Path, default=None)
    args = parser.parse_args()
    source = args.data_dir.expanduser().resolve(strict=True)
    database = source / "workbench.db"
    if not database.is_file() or database.is_symlink():
        parser.error("--data-dir must contain a regular workbench.db")
    evidence_base = args.evidence_dir.expanduser().resolve(strict=False)
    evidence_base.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    evidence_dir = evidence_base / run_id
    evidence_dir.mkdir(mode=0o700)
    started = datetime.now(UTC)
    summary: dict[str, Any] = {
        "schema": "vpw-restore-rehearsal.v1",
        "started_at": started.isoformat(),
        "source_kind": args.source_kind,
        "status": "failed",
        "private_content_retained": False,
        "stage": "source_inventory",
    }
    try:
        before = _files(source)
        summary["cache_symlinks_skipped"] = sum(
            (source / name).is_symlink() for name in ("provider-cache", "provider-snapshots")
        ) + sum(
            candidate.is_symlink()
            for name in ("provider-cache", "provider-snapshots")
            for candidate in (source / name).rglob("*")
            if (source / name).is_dir()
        )
        with tempfile.TemporaryDirectory(prefix="vpw-restore-rehearsal-") as temporary:
            sandbox = Path(temporary)
            backup_dir = sandbox / "backup"
            restored = sandbox / "restored"
            restored.mkdir(mode=0o700)
            backup_env = {
                **os.environ,
                "SQLITE_DATABASE_PATH": str(database),
                "WORKBENCH_ARTIFACT_ROOT": str(source),
                "WORKBENCH_ARTIFACT_MODE": "host",
                "BACKUP_DIR": str(backup_dir),
            }
            summary["stage"] = "backup"
            _run([str(SCRIPT_DIR / "workbench-backup.sh")], environment=backup_env)
            restore_env = {
                **os.environ,
                "SQLITE_DATABASE_PATH": str(restored / "workbench.db"),
                "ARTIFACT_RESTORE_ROOT": str(restored),
                "WORKBENCH_ARTIFACT_MODE": "host",
            }
            summary["stage"] = "restore"
            _run(
                [str(SCRIPT_DIR / "workbench-restore.sh"), str(backup_dir)], environment=restore_env
            )
            summary["stage"] = "artifact_comparison"
            after = _files(restored)
            if before != after:
                raise ValueError("Restored artifact inventory differs from source inventory.")
            summary["stage"] = "database_verification"
            db_state = _database_state(restored / "workbench.db", restored)
            ledger = args.vpw or Path(shutil.which("vpw") or SCRIPT_DIR.parent / ".venv/bin/vpw")
            if not ledger.is_file():
                raise ValueError(
                    "vpw command for strict Decision Ledger verification is unavailable."
                )
            summary["stage"] = "decision_ledger"
            _run(
                [str(ledger), "ledger", "verify", "--strict", "--data-dir", str(restored)],
                environment=os.environ.copy(),
            )
            summary.update(
                status="passed",
                stage="complete",
                database=db_state,
                artifacts={
                    "files_verified": len(after),
                    "bytes_verified": sum(size for size, _ in after.values()),
                },
                ledger_strict="passed",
            )
    except (OSError, ValueError, RuntimeError, sqlite3.Error, json.JSONDecodeError) as exc:
        summary["failure_type"] = type(exc).__name__
    finally:
        summary["completed_at"] = datetime.now(UTC).isoformat()
        summary["duration_seconds"] = round((datetime.now(UTC) - started).total_seconds(), 3)
        output = evidence_dir / "result.json"
        output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        output.chmod(0o600)
    print(f"Restore rehearsal {summary['status']}: {output}")
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
