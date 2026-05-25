"""Asset context CSV loading and normalization."""

from __future__ import annotations

import csv
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

from vuln_prioritizer.models import AssetContextRecord

from . import _occurrence_support


@dataclass(frozen=True)
class AssetContextRule:
    """Data representation and logic for Asset Context Rule."""

    rule_id: str
    target_kind: str
    target_ref: str
    asset_record: AssetContextRecord
    match_mode: str = "exact"
    precedence: int = 0
    order: int = 0


@dataclass(frozen=True)
class AssetContextLoadDiagnostics:
    """Data representation and logic for Asset Context Load Diagnostics."""

    total_rows: int
    loaded_rows: int
    skipped_rows: int
    exact_rules: int
    contains_rules: int
    regex_rules: int
    glob_rules: int
    basic_schema: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssetContextCatalog(Mapping[tuple[str, str], AssetContextRecord]):
    """Data representation and logic for Asset Context Catalog."""

    records: dict[tuple[str, str], AssetContextRecord]
    rules: tuple[AssetContextRule, ...]
    diagnostics: AssetContextLoadDiagnostics

    def __getitem__(self, key: tuple[str, str]) -> AssetContextRecord:
        """Getitem   method for AssetContextCatalog."""
        return self.records[key]

    def __iter__(self) -> Iterator[tuple[str, str]]:
        """Iter   method for AssetContextCatalog."""
        return iter(self.records)

    def __len__(self) -> int:
        """Len   method for AssetContextCatalog."""
        return len(self.records)


@overload
def load_asset_context_file(
    path: Path | None,
    *,
    return_diagnostics: Literal[False] = False,
) -> AssetContextCatalog:
    raise TypeError("overload declaration only")


@overload
def load_asset_context_file(
    path: Path | None,
    *,
    return_diagnostics: Literal[True],
) -> tuple[AssetContextCatalog, AssetContextLoadDiagnostics]:
    raise TypeError("overload declaration only")


def load_asset_context_file(
    path: Path | None,
    *,
    return_diagnostics: bool = False,
) -> AssetContextCatalog | tuple[AssetContextCatalog, AssetContextLoadDiagnostics]:
    """Load ordered asset context rules from CSV."""
    if path is None:
        empty = AssetContextCatalog(
            records={},
            rules=(),
            diagnostics=AssetContextLoadDiagnostics(
                total_rows=0,
                loaded_rows=0,
                skipped_rows=0,
                exact_rules=0,
                contains_rules=0,
                regex_rules=0,
                glob_rules=0,
                basic_schema=True,
            ),
        )
        return (empty, empty.diagnostics) if return_diagnostics else empty
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Asset context CSV is missing a header row.")
        fieldnames = {field.strip() for field in reader.fieldnames if field}
        required = {"target_kind", "asset_id"}
        missing = required - fieldnames
        has_target_ref = "target_ref" in fieldnames or "asset_ref" in fieldnames
        if missing or not has_target_ref:
            raise ValueError(
                "Asset context CSV must contain columns: target_kind, "
                "target_ref or asset_ref, asset_id."
            )

        optional_schema_fields = {"rule_id", "match_mode", "precedence"}
        basic_schema = not bool(optional_schema_fields & fieldnames)
        records: dict[tuple[str, str], AssetContextRecord] = {}
        rules: list[AssetContextRule] = []
        exact_rule_count = 0
        contains_rule_count = 0
        regex_rule_count = 0
        glob_rule_count = 0
        loaded_rows = 0
        total_rows = 0
        skipped_rows = 0
        warning_messages: list[str] = []
        duplicate_exact_rows = 0
        competing_rule_rows = 0
        seen_signatures: set[tuple[str, str, str, int]] = set()

        for order, row in enumerate(reader, start=1):
            total_rows += 1
            target_kind = (row.get("target_kind") or "").strip().lower()
            target_ref = (row.get("target_ref") or row.get("asset_ref") or "").strip()
            asset_id = (row.get("asset_id") or "").strip()
            if not target_kind or not target_ref or not asset_id:
                skipped_rows += 1
                continue
            loaded_rows += 1
            match_mode = (row.get("match_mode") or "exact").strip().lower()
            if match_mode not in {"exact", "contains", "regex", "glob"}:
                raise ValueError(
                    "Asset context CSV match_mode must be exact, contains, regex, or glob."
                )
            if match_mode == "regex":
                try:
                    _occurrence_support.validate_asset_context_regex(target_ref)
                except re.error as exc:
                    raise ValueError(
                        f"Asset context CSV regex at row {order} is invalid: {exc}."
                    ) from exc
                except ValueError as exc:
                    raise ValueError(
                        f"Asset context CSV regex at row {order} is unsafe: {exc}."
                    ) from exc
            precedence_raw = (row.get("precedence") or "").strip()
            if precedence_raw:
                try:
                    precedence = int(precedence_raw)
                except ValueError as exc:
                    raise ValueError(
                        f"Asset context CSV precedence must be an integer, got {precedence_raw!r}."
                    ) from exc
            else:
                precedence = order
            rule_id = (row.get("rule_id") or "").strip() or f"asset-rule:{order}"
            signature = (target_kind, target_ref, match_mode, precedence)
            if basic_schema and match_mode == "exact" and (target_kind, target_ref) in records:
                duplicate_exact_rows += 1
            elif signature in seen_signatures:
                competing_rule_rows += 1
            seen_signatures.add(signature)
            record = AssetContextRecord(
                target_kind=target_kind,
                target_ref=target_ref,
                asset_id=asset_id,
                rule_id=rule_id,
                match_mode=match_mode,
                precedence=precedence,
                row_number=order,
                criticality=_normalize_asset_criticality(
                    (row.get("criticality") or "").strip() or None,
                    warnings=warning_messages,
                    row_number=order,
                ),
                exposure=_normalize_asset_exposure(
                    (row.get("exposure") or "").strip() or None,
                    warnings=warning_messages,
                    row_number=order,
                ),
                environment=_normalize_asset_environment(
                    (row.get("environment") or "").strip() or None,
                    warnings=warning_messages,
                    row_number=order,
                ),
                owner=(row.get("owner") or "").strip() or None,
                business_service=(row.get("business_service") or "").strip() or None,
            )
            records[(target_kind, target_ref)] = record
            rules.append(
                AssetContextRule(
                    rule_id=rule_id,
                    target_kind=target_kind,
                    target_ref=target_ref,
                    asset_record=record,
                    match_mode=match_mode,
                    precedence=precedence,
                    order=order,
                )
            )
            if match_mode == "glob":
                glob_rule_count += 1
            elif match_mode == "regex":
                regex_rule_count += 1
            elif match_mode == "contains":
                contains_rule_count += 1
            else:
                exact_rule_count += 1

    if duplicate_exact_rows:
        warning_messages.append(
            "Asset context CSV contains "
            f"{duplicate_exact_rows} duplicate exact-match row(s); later rows remain preferred "
            "under basic-schema row order, but conflicts are now reported."
        )
    if competing_rule_rows:
        warning_messages.append(
            "Asset context CSV contains "
            f"{competing_rule_rows} rule(s) that compete on the same target pattern or "
            "precedence and may require deterministic tie-breaking."
        )

    catalog = AssetContextCatalog(
        records=records,
        rules=tuple(rules),
        diagnostics=AssetContextLoadDiagnostics(
            total_rows=total_rows,
            loaded_rows=loaded_rows,
            skipped_rows=skipped_rows,
            exact_rules=exact_rule_count,
            contains_rules=contains_rule_count,
            regex_rules=regex_rule_count,
            glob_rules=glob_rule_count,
            basic_schema=basic_schema,
            warnings=tuple(warning_messages),
        ),
    )
    return (catalog, catalog.diagnostics) if return_diagnostics else catalog


def _normalize_asset_criticality(
    value: str | None,
    *,
    warnings: list[str],
    row_number: int,
) -> str | None:
    """Normalize asset criticality function."""
    if value is None:
        return None
    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "crit": "critical",
        "critical": "critical",
        "high": "high",
        "med": "medium",
        "medium": "medium",
        "low": "low",
    }
    resolved = aliases.get(normalized)
    if resolved is None:
        warnings.append(
            f"Ignored unknown asset criticality at row {row_number}: {value!r}. "
            "Allowed values are low, medium, high, critical."
        )
    return resolved


def _normalize_asset_exposure(
    value: str | None,
    *,
    warnings: list[str],
    row_number: int,
) -> str | None:
    """Normalize asset exposure function."""
    if value is None:
        return None
    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "internal": "internal",
        "private": "internal",
        "dmz": "dmz",
        "internet": "internet-facing",
        "external": "internet-facing",
        "public": "internet-facing",
        "internet-facing": "internet-facing",
    }
    resolved = aliases.get(normalized)
    if resolved is None:
        warnings.append(
            f"Ignored unknown asset exposure at row {row_number}: {value!r}. "
            "Allowed values are internal, dmz, internet-facing."
        )
    return resolved


def _normalize_asset_environment(
    value: str | None,
    *,
    warnings: list[str],
    row_number: int,
) -> str | None:
    """Normalize asset environment function."""
    if value is None:
        return None
    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "prod": "prod",
        "production": "prod",
        "stage": "staging",
        "staging": "staging",
        "test": "test",
        "qa": "test",
        "dev": "dev",
        "development": "dev",
    }
    resolved = aliases.get(normalized)
    if resolved is None:
        warnings.append(
            f"Ignored unknown asset environment at row {row_number}: {value!r}. "
            "Allowed values are prod, staging, test, dev."
        )
    return resolved


__all__ = [
    "AssetContextRule",
    "AssetContextLoadDiagnostics",
    "AssetContextCatalog",
    "load_asset_context_file",
    "_normalize_asset_criticality",
    "_normalize_asset_exposure",
    "_normalize_asset_environment",
]
