"""State-related CLI support helpers."""

from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.state_store import SQLiteStateStore

from .common import exit_input_validation


def state_store_or_exit(db_path: Path, *, expect_existing: bool) -> SQLiteStateStore:
    if expect_existing and not db_path.exists():
        exit_input_validation(
            f"{db_path} does not exist. Run `state init` or `state import-snapshot` first."
        )
    return SQLiteStateStore(db_path)
