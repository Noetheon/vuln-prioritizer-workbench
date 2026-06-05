"""Analysis input and context loading helpers."""

from __future__ import annotations

from pathlib import Path

from app.domain.engine.inputs import (
    load_asset_context_file,
    load_vex_files,
)
from app.domain.engine.inputs.loader import AssetContextCatalog
from app.domain.engine.models import (
    ContextPolicyProfile,
    ProviderSnapshotReport,
    VexStatement,
    WaiverRule,
)
from app.domain.engine.provider_snapshot import load_provider_snapshot
from app.domain.engine.services.analysis_models import AnalysisInputError
from app.domain.engine.services.contextualization import (
    load_context_profile,
)
from app.domain.engine.services.waivers import (
    load_waiver_rules,
)


def load_asset_records(
    asset_context: Path | None,
) -> AssetContextCatalog:
    """Load asset records function."""
    try:
        return load_asset_context_file(asset_context)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_vex_statements(vex_files: list[Path]) -> list[VexStatement]:
    """Load vex statements function."""
    try:
        return load_vex_files(vex_files)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_analysis_waiver_rules(waiver_file: Path | None) -> list[WaiverRule]:
    """Load analysis waiver rules function."""
    try:
        return load_waiver_rules(waiver_file)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_analysis_context_profile(
    policy_profile: str,
    policy_file: Path | None,
) -> ContextPolicyProfile:
    """Load analysis context profile function."""
    try:
        return load_context_profile(policy_profile, policy_file)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_analysis_provider_snapshot(path: Path | None) -> ProviderSnapshotReport | None:
    """Load analysis provider snapshot function."""
    if path is None:
        return None
    try:
        return load_provider_snapshot(path)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc
