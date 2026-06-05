"""VEX file loading and diagnostics."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

from app.domain.engine.models import VexStatement

from . import _vex_support


@dataclass(frozen=True)
class VexLoadDiagnostics:
    """Data representation and logic for Vex Load Diagnostics."""

    file_count: int
    statement_count: int
    skipped_statements: int
    warnings: tuple[str, ...] = ()


@overload
def load_vex_files(
    paths: list[Path] | None,
    *,
    return_diagnostics: Literal[False] = False,
) -> list[VexStatement]:
    raise TypeError("overload declaration only")


@overload
def load_vex_files(
    paths: list[Path] | None,
    *,
    return_diagnostics: Literal[True],
) -> tuple[list[VexStatement], VexLoadDiagnostics]:
    raise TypeError("overload declaration only")


def load_vex_files(
    paths: list[Path] | None,
    *,
    return_diagnostics: bool = False,
) -> list[VexStatement] | tuple[list[VexStatement], VexLoadDiagnostics]:
    """Load all supported VEX files."""
    statements: list[VexStatement] = []
    skipped_statements = 0
    warning_messages: list[str] = []
    for file_order, path in enumerate(paths or [], start=1):
        if not path.exists() or not path.is_file():
            raise ValueError(f"VEX file does not exist: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"VEX JSON parsing failed for {path}: {exc.msg}.") from exc
        if not isinstance(document, dict):
            raise ValueError(f"VEX JSON root in {path} must be an object.")
        if isinstance(document, dict) and "statements" in document:
            if not isinstance(document.get("statements"), list):
                raise ValueError(f"OpenVEX JSON `statements` in {path} must be a list.")
            file_statements = _vex_support.parse_openvex_document(document)
            total_statements = len(document["statements"])
        elif (
            isinstance(document, dict)
            and "bomFormat" in document
            and "CycloneDX" in str(document.get("bomFormat"))
        ):
            if not isinstance(document.get("vulnerabilities"), list):
                raise ValueError(f"CycloneDX VEX JSON `vulnerabilities` in {path} must be a list.")
            warning_messages.extend(_vex_support.cyclonedx_vex_warnings(document))
            file_statements = _vex_support.parse_cyclonedx_vex_document(document)
            total_statements = len(document["vulnerabilities"])
        else:
            raise ValueError(
                f"Unsupported VEX format for {path}. Use OpenVEX JSON or CycloneDX VEX JSON."
            )
        loaded_statement_ids = {
            statement.source_record_id
            for statement in file_statements
            if statement.source_record_id
        }
        file_skipped = max(total_statements - len(loaded_statement_ids), 0)
        skipped_statements += file_skipped
        if file_skipped:
            warning_messages.append(
                f"Skipped {file_skipped} VEX statement(s) in {path} because required "
                "CVE, status, product, or affect data was missing or unsupported."
            )
        for statement_order, statement in enumerate(file_statements, start=1):
            statements.append(
                statement.model_copy(
                    update={
                        "source_path": str(path),
                        "source_file_order": file_order,
                        "statement_order": statement_order,
                    }
                )
            )
    diagnostics = VexLoadDiagnostics(
        file_count=len(paths or []),
        statement_count=len(statements),
        skipped_statements=skipped_statements,
        warnings=tuple(warning_messages),
    )
    return (statements, diagnostics) if return_diagnostics else statements


__all__ = [
    "VexLoadDiagnostics",
    "load_vex_files",
]
