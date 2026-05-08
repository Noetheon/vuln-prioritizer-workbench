from __future__ import annotations

from pathlib import Path

import pytest

from vuln_prioritizer.models import ProviderSnapshotReport
from vuln_prioritizer.services import analysis_inputs
from vuln_prioritizer.services.analysis_models import AnalysisInputError


@pytest.mark.parametrize(
    ("wrapper_name", "dependency_name", "args"),
    [
        ("load_asset_records_or_exit", "load_asset_context_file", (Path("assets.json"),)),
        ("load_vex_statements_or_exit", "load_vex_files", ([Path("vex.json")],)),
        ("load_waiver_rules_or_exit", "load_waiver_rules", (Path("waivers.yml"),)),
        (
            "load_context_profile_or_exit",
            "load_context_profile",
            ("enterprise", Path("policy.yml")),
        ),
        ("load_provider_snapshot_or_exit", "load_provider_snapshot", (Path("snapshot.json"),)),
    ],
)
def test_analysis_input_wrappers_translate_value_errors(
    monkeypatch: pytest.MonkeyPatch,
    wrapper_name: str,
    dependency_name: str,
    args: tuple[object, ...],
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise ValueError("bad input")

    monkeypatch.setattr(analysis_inputs, dependency_name, fail)

    with pytest.raises(AnalysisInputError, match="bad input"):
        getattr(analysis_inputs, wrapper_name)(*args)


def test_load_provider_snapshot_or_exit_skips_missing_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_path: Path) -> ProviderSnapshotReport:
        raise AssertionError("snapshot loader should not run without a path")

    monkeypatch.setattr(analysis_inputs, "load_provider_snapshot", fail)

    assert analysis_inputs.load_provider_snapshot_or_exit(None) is None
