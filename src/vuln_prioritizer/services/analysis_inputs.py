"""Analysis input and context loading helpers."""

from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.inputs import (
    load_asset_context_file,
    load_vex_files,
)
from vuln_prioritizer.inputs.loader import AssetContextCatalog
from vuln_prioritizer.models import (
    ContextPolicyProfile,
    ProviderSnapshotReport,
    VexStatement,
    WaiverRule,
)
from vuln_prioritizer.provider_snapshot import load_provider_snapshot
from vuln_prioritizer.services.analysis_models import AnalysisInputError
from vuln_prioritizer.services.contextualization import (
    load_context_profile,
)
from vuln_prioritizer.services.waivers import (
    load_waiver_rules,
)


def load_asset_records_or_exit(
    asset_context: Path | None,
) -> AssetContextCatalog:
    try:
        return load_asset_context_file(asset_context)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_vex_statements_or_exit(vex_files: list[Path]) -> list[VexStatement]:
    try:
        return load_vex_files(vex_files)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_waiver_rules_or_exit(waiver_file: Path | None) -> list[WaiverRule]:
    try:
        return load_waiver_rules(waiver_file)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_context_profile_or_exit(
    policy_profile: str,
    policy_file: Path | None,
) -> ContextPolicyProfile:
    try:
        return load_context_profile(policy_profile, policy_file)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_provider_snapshot_or_exit(path: Path | None) -> ProviderSnapshotReport | None:
    if path is None:
        return None
    try:
        return load_provider_snapshot(path)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc
