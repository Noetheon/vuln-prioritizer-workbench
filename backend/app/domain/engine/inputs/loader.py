"""Input normalization for CVE lists, scanners, SBOMs, asset context, and VEX."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from app.domain.engine.models import (
    AssetContextRecord,
    InputOccurrence,
    InputSourceSummary,
    ParsedInput,
    VexStatement,
)

from . import _occurrence_support, _vex_support
from .asset_context_loader import (
    AssetContextCatalog,
    AssetContextLoadDiagnostics,
    AssetContextRule,
    load_asset_context_file,
)
from .format_detection import (
    GENERIC_OCCURRENCE_CVE_FIELDS,
    GENERIC_OCCURRENCE_HINT_FIELDS,
    detect_input_format,
)
from .parser_registry import _INPUT_PARSERS, INPUT_PARSER_DEFINITIONS
from .vex_loader import VexLoadDiagnostics, load_vex_files


class InputLoader:
    """Load different source formats into a normalized occurrence model."""

    def load(
        self,
        path: Path,
        *,
        input_format: str = "auto",
        max_cves: int | None = None,
        target_kind: str | None = None,
        target_ref: str | None = None,
        asset_records: Mapping[tuple[str, str], AssetContextRecord] | None = None,
        vex_statements: list[VexStatement] | None = None,
    ) -> ParsedInput:
        """Load method for InputLoader."""
        return self.load_many(
            [InputSpec(path=path, input_format=input_format)],
            max_cves=max_cves,
            target_kind=target_kind,
            target_ref=target_ref,
            asset_records=asset_records,
            vex_statements=vex_statements,
        )

    def load_many(
        self,
        inputs: list[InputSpec],
        *,
        max_cves: int | None = None,
        target_kind: str | None = None,
        target_ref: str | None = None,
        asset_records: Mapping[tuple[str, str], AssetContextRecord] | None = None,
        vex_statements: list[VexStatement] | None = None,
    ) -> ParsedInput:
        """Load many method for InputLoader."""
        if not inputs:
            raise ValueError("At least one input file must be provided.")

        warnings: list[str] = []
        occurrences: list[InputOccurrence] = []
        source_summaries: list[InputSourceSummary] = []
        source_occurrence_groups: list[list[InputOccurrence]] = []
        resolved_formats: list[str] = []
        total_rows = 0
        asset_match_conflict_count = 0
        vex_conflict_count = 0

        catalog_diagnostics = getattr(asset_records, "diagnostics", None)
        if catalog_diagnostics and getattr(catalog_diagnostics, "warnings", None):
            warnings.extend(catalog_diagnostics.warnings)

        for spec in inputs:
            parsed = _load_single_input(spec.path, input_format=spec.input_format)
            resolved_formats.append(parsed.input_format)
            total_rows += parsed.total_rows
            warnings.extend(parsed.warnings)
            source_occurrences = [
                _occurrence_support.apply_manual_target(
                    occurrence,
                    target_kind=target_kind,
                    target_ref=target_ref,
                )
                for occurrence in parsed.occurrences
            ]
            source_occurrences, asset_diagnostics = _occurrence_support.apply_asset_context(
                source_occurrences,
                asset_records if asset_records is not None else {},
                return_diagnostics=True,
            )
            source_occurrences, vex_diagnostics = _vex_support.apply_vex_statements(
                source_occurrences,
                vex_statements or [],
                return_diagnostics=True,
            )
            warnings.extend(asset_diagnostics.warnings)
            warnings.extend(vex_diagnostics.warnings)
            asset_match_conflict_count += asset_diagnostics.ambiguous_occurrences
            vex_conflict_count += vex_diagnostics.conflict_occurrences
            occurrences.extend(source_occurrences)
            source_occurrence_groups.append(source_occurrences)
            source_summaries.append(
                InputSourceSummary(
                    input_path=str(spec.path),
                    input_format=parsed.input_format,
                    total_rows=parsed.total_rows,
                    occurrence_count=len(source_occurrences),
                    unique_cves=_count_unique_cves(source_occurrences),
                    warning_count=len(parsed.warnings),
                )
            )

        parsed = _occurrence_support.finalize_occurrences(
            occurrences,
            input_format=_effective_input_format(resolved_formats),
            warnings=warnings,
            total_rows=total_rows,
            max_cves=max_cves,
            input_paths=[str(spec.path) for spec in inputs],
            source_summaries=source_summaries,
            merged_input_count=len(inputs),
            asset_match_conflict_count=asset_match_conflict_count,
            vex_conflict_count=vex_conflict_count,
        )
        included_cves = set(parsed.unique_cves)
        return parsed.model_copy(
            update={
                "source_summaries": [
                    summary.model_copy(
                        update={
                            "included_occurrence_count": len(
                                [
                                    occurrence
                                    for occurrence in source_occurrences
                                    if occurrence.cve_id in included_cves
                                ]
                            ),
                            "included_unique_cves": _count_unique_cves(
                                [
                                    occurrence
                                    for occurrence in source_occurrences
                                    if occurrence.cve_id in included_cves
                                ]
                            ),
                        }
                    )
                    for summary, source_occurrences in zip(
                        parsed.source_summaries,
                        source_occurrence_groups,
                        strict=True,
                    )
                ]
            }
        )


@dataclass(frozen=True)
class InputSpec:
    """Data representation and logic for Input Spec."""

    path: Path
    input_format: str = "auto"


def _count_unique_cves(occurrences: list[InputOccurrence]) -> int:
    """Count unique cves function."""
    return len({occurrence.cve_id for occurrence in occurrences})


def _effective_input_format(resolved_formats: list[str]) -> str:
    """Effective input format function."""
    unique_formats = {item for item in resolved_formats if item}
    if len(unique_formats) <= 1:
        return resolved_formats[0] if resolved_formats else "cve-list"
    return "mixed"


def _load_single_input(
    path: Path,
    *,
    input_format: str,
) -> ParsedInput:
    """Load single input function."""
    if not path.exists() or not path.is_file():
        raise ValueError(f"Input file does not exist: {path}")

    resolved_format = detect_input_format(path, explicit_format=input_format)
    parser = _INPUT_PARSERS.get(resolved_format)
    if parser is None:
        raise ValueError(f"Unsupported input format: {resolved_format}")
    return parser(path)


def build_inline_input(
    cve_id: str,
    *,
    target_kind: str | None = None,
    target_ref: str | None = None,
    asset_records: Mapping[tuple[str, str], AssetContextRecord] | None = None,
    vex_statements: list[VexStatement] | None = None,
) -> ParsedInput:
    """Build a parsed input for a single inline CVE."""
    occurrence = InputOccurrence(
        cve_id=cve_id,
        source_format="cve-list",
        source_record_id="inline:1",
        target_kind=(target_kind or "generic").lower(),
        target_ref=target_ref,
    )
    occurrences, asset_diagnostics = _occurrence_support.apply_asset_context(
        [occurrence],
        asset_records if asset_records is not None else {},
        return_diagnostics=True,
    )
    occurrences, vex_diagnostics = _vex_support.apply_vex_statements(
        occurrences,
        vex_statements or [],
        return_diagnostics=True,
    )
    return _occurrence_support.finalize_occurrences(
        occurrences,
        input_format="cve-list",
        warnings=[
            *asset_diagnostics.warnings,
            *vex_diagnostics.warnings,
        ],
        total_rows=1,
        max_cves=1,
        asset_match_conflict_count=asset_diagnostics.ambiguous_occurrences,
        vex_conflict_count=vex_diagnostics.conflict_occurrences,
    )


__all__ = [
    "AssetContextCatalog",
    "AssetContextLoadDiagnostics",
    "AssetContextRule",
    "GENERIC_OCCURRENCE_CVE_FIELDS",
    "GENERIC_OCCURRENCE_HINT_FIELDS",
    "INPUT_PARSER_DEFINITIONS",
    "InputLoader",
    "InputSpec",
    "VexLoadDiagnostics",
    "_INPUT_PARSERS",
    "build_inline_input",
    "detect_input_format",
    "load_asset_context_file",
    "load_vex_files",
]
