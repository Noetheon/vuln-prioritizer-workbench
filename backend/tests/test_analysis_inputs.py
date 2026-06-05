from __future__ import annotations

from pathlib import Path

import pytest

from app.domain.engine.models import ProviderSnapshotReport
from app.domain.engine.services import analysis_inputs
from app.domain.engine.services.analysis_models import AnalysisInputError


@pytest.mark.parametrize(
    ("wrapper_name", "dependency_name", "args"),
    [
        ("load_asset_records", "load_asset_context_file", (Path("assets.json"),)),
        ("load_vex_statements", "load_vex_files", ([Path("vex.json")],)),
        ("load_analysis_waiver_rules", "load_waiver_rules", (Path("waivers.yml"),)),
        (
            "load_analysis_context_profile",
            "load_context_profile",
            ("enterprise", Path("policy.yml")),
        ),
        ("load_analysis_provider_snapshot", "load_provider_snapshot", (Path("snapshot.json"),)),
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


def test_load_analysis_provider_snapshot_skips_missing_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_path: Path) -> ProviderSnapshotReport:
        raise AssertionError("snapshot loader should not run without a path")

    monkeypatch.setattr(analysis_inputs, "load_provider_snapshot", fail)

    assert analysis_inputs.load_analysis_provider_snapshot(None) is None
