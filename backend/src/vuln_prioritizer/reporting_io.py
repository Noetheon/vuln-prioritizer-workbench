"""Filesystem helpers for generated reports."""

from __future__ import annotations

from pathlib import Path


def write_output(path: Path, content: str) -> None:
    """Write report content to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized_content = content if content.endswith("\n") else content + "\n"
    normalized_lines = [line.rstrip() for line in normalized_content.splitlines()]
    path.write_text("\n".join(normalized_lines) + "\n", encoding="utf-8")
