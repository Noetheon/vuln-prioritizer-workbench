"""Project-level runtime configuration discovery and loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import AliasChoices, Field, ValidationError

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
    provider_snapshot_file: str | None = None
    locked_provider_data: bool | None = None
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
    fail_on_provider_error: bool | None = None
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
    fail_on_provider_error: bool | None = None


class ExplainDefaults(StrictModel):
    format: str | None = None
    show_suppressed: bool | None = None
    fail_on_provider_error: bool | None = None


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
    fail_on_provider_error: bool | None = None


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


class AttackValidateDefaults(StrictModel):
    attack_source: str | None = None
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    format: str | None = None


class AttackCoverageDefaults(AttackValidateDefaults):
    max_cves: int | None = None


class AttackNavigatorLayerDefaults(StrictModel):
    attack_source: str | None = None
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    max_cves: int | None = None


class AttackDefaults(StrictModel):
    validate_command: AttackValidateDefaults = Field(
        default_factory=AttackValidateDefaults,
        validation_alias=AliasChoices("validate", "validate_command"),
    )
    coverage: AttackCoverageDefaults = Field(default_factory=AttackCoverageDefaults)
    navigator_layer: AttackNavigatorLayerDefaults = Field(
        default_factory=AttackNavigatorLayerDefaults,
        validation_alias=AliasChoices("navigator-layer", "navigator_layer"),
    )


class DataStatusDefaults(StrictModel):
    cache_dir: str | None = None
    cache_ttl_hours: int | None = None
    offline_kev_file: str | None = None
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    format: str | None = None
    quiet: bool | None = None


class DataUpdateDefaults(StrictModel):
    source: list[str] = Field(default_factory=list)
    input_format: str | None = None
    max_cves: int | None = None
    cache_dir: str | None = None
    cache_ttl_hours: int | None = None
    offline_kev_file: str | None = None
    nvd_api_key_env: str | None = None
    format: str | None = None
    quiet: bool | None = None


class DataVerifyDefaults(StrictModel):
    input_format: str | None = None
    max_cves: int | None = None
    cache_dir: str | None = None
    cache_ttl_hours: int | None = None
    offline_kev_file: str | None = None
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None
    format: str | None = None
    quiet: bool | None = None


class DataExportProviderSnapshotDefaults(StrictModel):
    source: list[str] = Field(default_factory=list)
    input_format: str | None = None
    max_cves: int | None = None
    cache_dir: str | None = None
    cache_ttl_hours: int | None = None
    offline_kev_file: str | None = None
    nvd_api_key_env: str | None = None
    cache_only: bool | None = None


class DataDefaults(StrictModel):
    status: DataStatusDefaults = Field(default_factory=DataStatusDefaults)
    update: DataUpdateDefaults = Field(default_factory=DataUpdateDefaults)
    verify: DataVerifyDefaults = Field(default_factory=DataVerifyDefaults)
    export_provider_snapshot: DataExportProviderSnapshotDefaults = Field(
        default_factory=DataExportProviderSnapshotDefaults,
        validation_alias=AliasChoices("export-provider-snapshot", "export_provider_snapshot"),
    )


class CommandDefaults(StrictModel):
    analyze: AnalyzeDefaults = Field(default_factory=AnalyzeDefaults)
    compare: CompareDefaults = Field(default_factory=CompareDefaults)
    explain: ExplainDefaults = Field(default_factory=ExplainDefaults)
    doctor: DoctorDefaults = Field(default_factory=DoctorDefaults)
    snapshot: SnapshotDefaults = Field(default_factory=SnapshotDefaults)
    rollup: RollupDefaults = Field(default_factory=RollupDefaults)
    attack: AttackDefaults = Field(default_factory=AttackDefaults)
    data: DataDefaults = Field(default_factory=DataDefaults)


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
    general = _normalize_multi_value_option_defaults(general, option_names={"input_format"})
    attack_general = _compact_defaults(
        {
            "attack_source": loaded.document.defaults.attack_source,
            "attack_mapping_file": loaded.document.defaults.attack_mapping_file,
            "attack_technique_metadata_file": (
                loaded.document.defaults.attack_technique_metadata_file
            ),
        }
    )
    data_general = _compact_defaults(
        {
            "cache_dir": loaded.document.defaults.cache_dir,
            "cache_ttl_hours": loaded.document.defaults.cache_ttl_hours,
            "offline_kev_file": loaded.document.defaults.offline_kev_file,
            "nvd_api_key_env": loaded.document.defaults.nvd_api_key_env,
        }
    )
    default_map: dict[str, Any] = {
        "analyze": {
            **general,
            **_normalize_multi_value_option_defaults(
                _compact_defaults(loaded.document.commands.analyze.model_dump()),
                option_names={"input_format"},
            ),
        },
        "compare": {
            **general,
            **_normalize_multi_value_option_defaults(
                _compact_defaults(loaded.document.commands.compare.model_dump()),
                option_names={"input_format"},
            ),
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
                **_normalize_multi_value_option_defaults(
                    _compact_defaults(loaded.document.commands.snapshot.create.model_dump()),
                    option_names={"input_format"},
                ),
            },
            "diff": _compact_defaults(loaded.document.commands.snapshot.diff.model_dump()),
        },
        "attack": {
            "validate": {
                **attack_general,
                **_compact_defaults(loaded.document.commands.attack.validate_command.model_dump()),
            },
            "coverage": {
                **attack_general,
                **_compact_defaults(loaded.document.commands.attack.coverage.model_dump()),
            },
            "navigator-layer": {
                **attack_general,
                **_compact_defaults(loaded.document.commands.attack.navigator_layer.model_dump()),
            },
        },
        "data": {
            "status": {
                **data_general,
                **_compact_defaults(
                    {
                        "attack_mapping_file": loaded.document.defaults.attack_mapping_file,
                        "attack_technique_metadata_file": (
                            loaded.document.defaults.attack_technique_metadata_file
                        ),
                    }
                ),
                **_compact_defaults(loaded.document.commands.data.status.model_dump()),
            },
            "update": {
                **data_general,
                **_normalize_multi_value_option_defaults(
                    _compact_defaults(loaded.document.commands.data.update.model_dump()),
                    option_names={"input_format", "source"},
                ),
            },
            "verify": {
                **data_general,
                **_compact_defaults(
                    {
                        "attack_mapping_file": loaded.document.defaults.attack_mapping_file,
                        "attack_technique_metadata_file": (
                            loaded.document.defaults.attack_technique_metadata_file
                        ),
                    }
                ),
                **_normalize_multi_value_option_defaults(
                    _compact_defaults(loaded.document.commands.data.verify.model_dump()),
                    option_names={"input_format"},
                ),
            },
            "export-provider-snapshot": {
                **data_general,
                **_normalize_multi_value_option_defaults(
                    _compact_defaults(
                        loaded.document.commands.data.export_provider_snapshot.model_dump()
                    ),
                    option_names={"input_format", "source"},
                ),
            },
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
        "Provider snapshot file": defaults.provider_snapshot_file,
        "Cache directory": defaults.cache_dir,
    }
    for label, value in scalar_paths.items():
        if value:
            file_entries.append((label, Path(value)))
    command_path_entries = {
        "ATT&CK validate mapping file": (
            loaded.document.commands.attack.validate_command.attack_mapping_file
        ),
        "ATT&CK validate technique metadata file": (
            loaded.document.commands.attack.validate_command.attack_technique_metadata_file
        ),
        "ATT&CK coverage mapping file": (
            loaded.document.commands.attack.coverage.attack_mapping_file
        ),
        "ATT&CK coverage technique metadata file": (
            loaded.document.commands.attack.coverage.attack_technique_metadata_file
        ),
        "ATT&CK navigator mapping file": (
            loaded.document.commands.attack.navigator_layer.attack_mapping_file
        ),
        "ATT&CK navigator technique metadata file": (
            loaded.document.commands.attack.navigator_layer.attack_technique_metadata_file
        ),
        "Data status offline KEV file": loaded.document.commands.data.status.offline_kev_file,
        "Data status ATT&CK mapping file": (
            loaded.document.commands.data.status.attack_mapping_file
        ),
        "Data status ATT&CK technique metadata file": (
            loaded.document.commands.data.status.attack_technique_metadata_file
        ),
        "Data update offline KEV file": loaded.document.commands.data.update.offline_kev_file,
        "Data verify offline KEV file": loaded.document.commands.data.verify.offline_kev_file,
        "Data verify ATT&CK mapping file": (
            loaded.document.commands.data.verify.attack_mapping_file
        ),
        "Data verify ATT&CK technique metadata file": (
            loaded.document.commands.data.verify.attack_technique_metadata_file
        ),
        "Provider snapshot offline KEV file": (
            loaded.document.commands.data.export_provider_snapshot.offline_kev_file
        ),
        "Data status cache directory": loaded.document.commands.data.status.cache_dir,
        "Data update cache directory": loaded.document.commands.data.update.cache_dir,
        "Data verify cache directory": loaded.document.commands.data.verify.cache_dir,
        "Provider snapshot cache directory": (
            loaded.document.commands.data.export_provider_snapshot.cache_dir
        ),
    }
    for label, value in command_path_entries.items():
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


def _normalize_multi_value_option_defaults(
    defaults: dict[str, Any],
    *,
    option_names: set[str],
) -> dict[str, Any]:
    normalized = dict(defaults)
    for option_name in option_names:
        value = normalized.get(option_name)
        if isinstance(value, str):
            normalized[option_name] = [value]
    return normalized


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
        "provider_snapshot_file",
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

    commands = normalized.get("commands")
    if isinstance(commands, dict):
        _normalize_command_path_defaults(commands, base_dir=base_dir)

    return normalized


def _normalize_command_path_defaults(commands: dict[str, Any], *, base_dir: Path) -> None:
    attack_commands = commands.get("attack")
    if isinstance(attack_commands, dict):
        for command_name in ("validate", "coverage", "navigator-layer", "navigator_layer"):
            command = attack_commands.get(command_name)
            if isinstance(command, dict):
                _resolve_path_fields(
                    command,
                    base_dir=base_dir,
                    path_keys={"attack_mapping_file", "attack_technique_metadata_file"},
                )

    data_commands = commands.get("data")
    if isinstance(data_commands, dict):
        for command_name in (
            "status",
            "update",
            "verify",
            "export-provider-snapshot",
            "export_provider_snapshot",
        ):
            command = data_commands.get(command_name)
            if isinstance(command, dict):
                _resolve_path_fields(
                    command,
                    base_dir=base_dir,
                    path_keys={
                        "offline_kev_file",
                        "attack_mapping_file",
                        "attack_technique_metadata_file",
                        "cache_dir",
                    },
                )


def _resolve_path_fields(
    document: dict[str, Any],
    *,
    base_dir: Path,
    path_keys: set[str],
) -> None:
    for key in path_keys:
        value = document.get(key)
        if isinstance(value, str) and value:
            document[key] = str(_resolve_relative_path(value, base_dir=base_dir))


def _resolve_relative_path(value: str, *, base_dir: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return (base_dir / path).resolve()
