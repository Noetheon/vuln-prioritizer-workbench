"""Project-level runtime configuration discovery and loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError

from vuln_prioritizer.models import StrictModel

CONFIG_FILENAME = "vuln-prioritizer.yml"


class CommonDefaults(StrictModel):
    attack_source: str | None = None
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    asset_context: str | None = None
    vex_file: list[str] = Field(default_factory=list)
    policy_profile: str | None = None
    policy_file: str | None = None
    waiver_file: str | None = None
    target_kind: str | None = None
    target_ref: str | None = None
    offline_kev_file: str | None = None
    offline_attack_file: str | None = None
    nvd_api_key_env: str | None = None
    cache_dir: str | None = None
    cache_ttl_hours: int | None = None
    no_cache: bool | None = None
    critical_epss_threshold: float | None = None
    critical_cvss_threshold: float | None = None
    high_epss_threshold: float | None = None
    high_cvss_threshold: float | None = None
    medium_epss_threshold: float | None = None
    medium_cvss_threshold: float | None = None
    max_cves: int | None = None


class AnalyzeDefaults(StrictModel):
    format: str | None = None
    input_format: str | None = None
    priority: list[str] = Field(default_factory=list)
    kev_only: bool | None = None
    min_cvss: float | None = None
    min_epss: float | None = None
    sort_by: str | None = None
    show_suppressed: bool | None = None
    hide_waived: bool | None = None
    fail_on: str | None = None
    fail_on_expired_waivers: bool | None = None
    fail_on_review_due_waivers: bool | None = None


class CompareDefaults(StrictModel):
    format: str | None = None
    input_format: str | None = None
    priority: list[str] = Field(default_factory=list)
    kev_only: bool | None = None
    min_cvss: float | None = None
    min_epss: float | None = None
    sort_by: str | None = None
    show_suppressed: bool | None = None
    hide_waived: bool | None = None


class ExplainDefaults(StrictModel):
    format: str | None = None
    show_suppressed: bool | None = None


class DoctorDefaults(StrictModel):
    format: str | None = None
    live: bool | None = None


class SnapshotCreateDefaults(StrictModel):
    format: str | None = None
    input_format: str | None = None
    priority: list[str] = Field(default_factory=list)
    kev_only: bool | None = None
    min_cvss: float | None = None
    min_epss: float | None = None
    sort_by: str | None = None
    show_suppressed: bool | None = None
    hide_waived: bool | None = None


class SnapshotDiffDefaults(StrictModel):
    format: str | None = None
    include_unchanged: bool | None = None


class SnapshotDefaults(StrictModel):
    create: SnapshotCreateDefaults = Field(default_factory=SnapshotCreateDefaults)
    diff: SnapshotDiffDefaults = Field(default_factory=SnapshotDiffDefaults)


class RollupDefaults(StrictModel):
    format: str | None = None
    by: str | None = None
    top: int | None = None


class CommandDefaults(StrictModel):
    analyze: AnalyzeDefaults = Field(default_factory=AnalyzeDefaults)
    compare: CompareDefaults = Field(default_factory=CompareDefaults)
    explain: ExplainDefaults = Field(default_factory=ExplainDefaults)
    doctor: DoctorDefaults = Field(default_factory=DoctorDefaults)
    snapshot: SnapshotDefaults = Field(default_factory=SnapshotDefaults)
    rollup: RollupDefaults = Field(default_factory=RollupDefaults)


class RuntimeConfigDocument(StrictModel):
    version: int = 1
    defaults: CommonDefaults = Field(default_factory=CommonDefaults)
    commands: CommandDefaults = Field(default_factory=CommandDefaults)


class LoadedRuntimeConfig(StrictModel):
    path: Path
    document: RuntimeConfigDocument


def discover_runtime_config(start_dir: Path) -> Path | None:
    """Find the nearest runtime config by walking up the directory tree."""
    current = start_dir.resolve()
    for directory in [current, *current.parents]:
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_runtime_config(path: Path) -> LoadedRuntimeConfig:
    """Load and normalize a runtime config document."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"{path} could not be read: {exc}") from exc

    try:
        raw_document = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"{path} is not valid YAML: {exc}") from exc

    if not isinstance(raw_document, dict):
        raise ValueError(f"{path} must contain a YAML object at the top level.")

    normalized = _normalize_runtime_document(raw_document, base_dir=path.parent.resolve())
    try:
        document = RuntimeConfigDocument.model_validate(normalized)
    except ValidationError as exc:
        raise ValueError(f"{path} is not a valid runtime config: {exc}") from exc
    return LoadedRuntimeConfig(path=path.resolve(), document=document)


def build_cli_default_map(loaded: LoadedRuntimeConfig) -> dict[str, Any]:
    """Build a Click/Typer default_map from the loaded config."""
    general = _compact_defaults(loaded.document.defaults.model_dump())
    default_map: dict[str, Any] = {
        "analyze": {
            **general,
            **_compact_defaults(loaded.document.commands.analyze.model_dump()),
        },
        "compare": {
            **general,
            **_compact_defaults(loaded.document.commands.compare.model_dump()),
        },
        "explain": {
            **general,
            **_compact_defaults(loaded.document.commands.explain.model_dump()),
        },
        "doctor": {
            **_compact_defaults(loaded.document.commands.doctor.model_dump()),
            **_compact_defaults(
                {
                    "waiver_file": loaded.document.defaults.waiver_file,
                    "cache_dir": loaded.document.defaults.cache_dir,
                    "cache_ttl_hours": loaded.document.defaults.cache_ttl_hours,
                    "offline_kev_file": loaded.document.defaults.offline_kev_file,
                    "attack_mapping_file": loaded.document.defaults.attack_mapping_file,
                    "attack_technique_metadata_file": (
                        loaded.document.defaults.attack_technique_metadata_file
                    ),
                }
            ),
        },
        "rollup": _compact_defaults(loaded.document.commands.rollup.model_dump()),
        "snapshot": {
            "create": {
                **general,
                **_compact_defaults(loaded.document.commands.snapshot.create.model_dump()),
            },
            "diff": _compact_defaults(loaded.document.commands.snapshot.diff.model_dump()),
        },
    }
    return default_map


def collect_referenced_files(loaded: LoadedRuntimeConfig) -> list[tuple[str, Path]]:
    """Return deduplicated file references described by the runtime config."""
    file_entries: list[tuple[str, Path]] = []
    defaults = loaded.document.defaults
    scalar_paths = {
        "ATT&CK mapping file": defaults.attack_mapping_file,
        "ATT&CK technique metadata file": defaults.attack_technique_metadata_file,
        "Asset context file": defaults.asset_context,
        "Policy file": defaults.policy_file,
        "Waiver file": defaults.waiver_file,
        "Offline KEV file": defaults.offline_kev_file,
        "Offline ATT&CK file": defaults.offline_attack_file,
        "Cache directory": defaults.cache_dir,
    }
    for label, value in scalar_paths.items():
        if value:
            file_entries.append((label, Path(value)))
    for vex_file in defaults.vex_file:
        file_entries.append(("VEX file", Path(vex_file)))

    unique: list[tuple[str, Path]] = []
    seen: set[tuple[str, Path]] = set()
    for label, path in file_entries:
        key = (label, path)
        if key in seen:
            continue
        seen.add(key)
        unique.append((label, path))
    return unique


def _compact_defaults(document: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key, value in document.items():
        if value is None:
            continue
        if isinstance(value, list) and not value:
            continue
        compact[key] = value
    return compact


def _normalize_runtime_document(document: dict[str, Any], *, base_dir: Path) -> dict[str, Any]:
    normalized = yaml.safe_load(yaml.safe_dump(document)) or {}
    path_keys = {
        "attack_mapping_file",
        "attack_technique_metadata_file",
        "asset_context",
        "policy_file",
        "waiver_file",
        "offline_kev_file",
        "offline_attack_file",
        "cache_dir",
    }

    defaults = normalized.get("defaults")
    if isinstance(defaults, dict):
        for key in path_keys:
            if defaults.get(key):
                defaults[key] = str(_resolve_relative_path(defaults[key], base_dir=base_dir))
        if isinstance(defaults.get("vex_file"), list):
            defaults["vex_file"] = [
                str(_resolve_relative_path(item, base_dir=base_dir))
                for item in defaults["vex_file"]
                if item
            ]

    return normalized


def _resolve_relative_path(value: str, *, base_dir: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return (base_dir / path).resolve()
