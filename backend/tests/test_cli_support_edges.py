from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
import typer

from vuln_prioritizer.cli_options import AttackSource
from vuln_prioritizer.cli_support import analysis as cli_analysis
from vuln_prioritizer.cli_support import attack_support, data_support, doctor_support
from vuln_prioritizer.cli_support import common as cli_common
from vuln_prioritizer.cli_support import state as state_support
from vuln_prioritizer.cli_support.common import TableJsonOutputFormat
from vuln_prioritizer.models import AttackData, AttackSummary
from vuln_prioritizer.services.analysis import AnalysisInputError, AnalysisNoFindingsError


class _ExitSentinel(RuntimeError):
    pass


def _raise_validation(message: str) -> None:
    raise _ExitSentinel(message)


@pytest.mark.parametrize(
    ("public_name", "private_name"),
    [
        ("build_priority_policy", "_build_priority_policy"),
        ("load_asset_records_or_exit", "_load_asset_records"),
        ("load_vex_statements_or_exit", "_load_vex_statements"),
        ("load_waiver_rules_or_exit", "_load_waiver_rules"),
        ("load_context_profile_or_exit", "_load_context_profile"),
        ("load_provider_snapshot_or_exit", "_load_provider_snapshot"),
        ("validate_requested_attack_mode", "_validate_requested_attack_mode"),
        ("build_findings", "_build_findings"),
        ("prepare_saved_explain", "_prepare_saved_explain"),
    ],
)
def test_analysis_facade_translates_input_errors(
    monkeypatch: pytest.MonkeyPatch,
    public_name: str,
    private_name: str,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AnalysisInputError("invalid analysis input")

    monkeypatch.setattr(cli_analysis, private_name, fail)
    monkeypatch.setattr(cli_analysis, "exit_input_validation", _raise_validation)

    with pytest.raises(_ExitSentinel, match="invalid analysis input"):
        getattr(cli_analysis, public_name)()


def test_prepare_analysis_and_explain_exit_cleanly_when_no_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_findings(*_args: object, **_kwargs: object) -> None:
        raise AnalysisNoFindingsError("no active findings")

    monkeypatch.setattr(cli_analysis, "_prepare_analysis", no_findings)
    monkeypatch.setattr(cli_analysis, "_prepare_explain", no_findings)

    with pytest.raises(typer.Exit) as analysis_exit:
        cli_analysis.prepare_analysis(object())  # type: ignore[arg-type]
    assert analysis_exit.value.exit_code == 1

    with pytest.raises(typer.Exit) as explain_exit:
        cli_analysis.prepare_explain(object())  # type: ignore[arg-type]
    assert explain_exit.value.exit_code == 1


def test_analysis_policy_fail_on_edges() -> None:
    review_due_context = SimpleNamespace(
        expired_waiver_count=0,
        waiver_review_due_count=1,
    )
    with pytest.raises(typer.Exit) as waiver_exit:
        cli_analysis.handle_waiver_lifecycle_fail_on(
            review_due_context,  # type: ignore[arg-type]
            fail_on_expired_waivers=False,
            fail_on_review_due_waivers=True,
        )
    assert waiver_exit.value.exit_code == 1

    stale_context = SimpleNamespace(provider_stale=True, provider_stale_sources=["epss", "nvd"])
    with pytest.raises(typer.Exit) as stale_exit:
        cli_analysis.handle_provider_staleness_fail_on(
            stale_context,  # type: ignore[arg-type]
            fail_on_stale_provider_data=True,
        )
    assert stale_exit.value.exit_code == 1


def test_common_cli_validation_helpers_cover_runtime_and_merge_edges(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assert cli_common.load_runtime_config_for_session(config=None, no_config=True) is None
    assert cli_common.merge_default_maps(
        {"outer": {"keep": 1, "replace": 2}, "plain": "old"},
        {"outer": {"replace": 3, "new": 4}, "plain": "new"},
    ) == {"outer": {"keep": 1, "replace": 3, "new": 4}, "plain": "new"}

    monkeypatch.setattr(cli_common, "exit_input_validation", _raise_validation)
    with pytest.raises(_ExitSentinel, match="requires at least one --input"):
        cli_common.build_input_specs_or_exit(
            input_paths=[],
            input_formats=None,
            command_name="analyze",
            require_inputs=True,
        )
    with pytest.raises(typer.Exit) as format_exit:
        cli_common.validate_command_formats(
            command_name="data status",
            format=AttackSource.local_csv,
            allowed_formats=set(cli_common.TABLE_AND_JSON_OUTPUT_FORMATS),
        )
    assert format_exit.value.exit_code == 2

    def fake_load_runtime_config(_path: Path) -> object:
        raise ValueError("bad runtime config")

    monkeypatch.setattr(cli_common, "load_runtime_config", fake_load_runtime_config)
    with pytest.raises(_ExitSentinel, match="bad runtime config"):
        cli_common.load_runtime_config_for_session(config=tmp_path / "vp.yml", no_config=False)


def test_data_support_cache_coverage_tracks_empty_and_invalid_records(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeCache:
        def __init__(self, payloads: dict[tuple[str, str], object]) -> None:
            self.payloads = payloads

        def get_json(self, namespace: str, key: str) -> object:
            return self.payloads.get((namespace, key))

    cache = FakeCache(
        {
            ("nvd", "CVE-2024-0001"): {"cve_id": "CVE-2024-0001", "description": "known"},
            ("nvd", "CVE-2024-0002"): {"cve_id": "CVE-2024-0002"},
            ("nvd", "CVE-2024-0003"): {"cve_id": 123},
            ("epss", "CVE-2024-0001"): {"cve_id": "CVE-2024-0001", "epss": 0.1},
            ("epss", "CVE-2024-0002"): {"cve_id": "CVE-2024-0002"},
            ("epss", "CVE-2024-0003"): {"cve_id": 123},
            (
                "kev",
                "catalog",
            ): {
                "CVE-2024-0001": {"cve_id": "CVE-2024-0001", "in_kev": True},
                "CVE-2024-0003": {"cve_id": 123},
            },
        }
    )

    assert data_support.build_cache_coverage_items(cache=cache, cve_ids=[]) == []  # type: ignore[arg-type]
    coverage = data_support.build_cache_coverage_items(
        cache=cache,  # type: ignore[arg-type]
        cve_ids=["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
    )

    by_source = {item["source"]: item for item in coverage}
    assert by_source["nvd"]["cached_hits"] == 1
    assert by_source["nvd"]["empty_records"] == 1
    assert by_source["nvd"]["invalid_records"] == 1
    assert by_source["epss"]["cached_hits"] == 1
    assert by_source["epss"]["empty_records"] == 1
    assert by_source["epss"]["invalid_records"] == 1
    assert by_source["kev"]["cached_hits"] == 1
    assert by_source["kev"]["invalid_records"] == 1

    monkeypatch.setattr(data_support, "exit_input_validation", _raise_validation)
    with pytest.raises(_ExitSentinel, match="--quiet"):
        data_support.validate_data_output_options(
            command_name="data status",
            format=TableJsonOutputFormat.table,
            output=None,
            quiet=True,
        )

    payload = data_support.build_data_status_payload(
        cache_dir=tmp_path / "cache",
        cache_ttl_hours=24,
        output=tmp_path / "status.json",
        offline_kev_file=tmp_path / "kev.json",
        statuses=[
            {
                "namespace": "nvd",
                "file_count": True,
                "valid_count": "2",
                "expired_count": 0,
                "invalid_count": 0,
            }
        ],
        attack_validation=None,
        attack_mapping_sha256=None,
        attack_metadata_sha256=None,
        warnings=["cache warmup pending"],
    )
    assert payload["summary"]["namespace_file_count"] == 1
    with pytest.raises(TypeError, match="Expected an integer-like value"):
        data_support._coerce_int(object())


def test_state_support_requires_existing_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(state_support, "exit_input_validation", _raise_validation)
    with pytest.raises(_ExitSentinel, match="state init"):
        state_support.state_store_or_exit(tmp_path / "missing.db", expect_existing=True)


def test_attack_validate_local_curated_reports_quality_and_ignored_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _FakeCuratedProvider:
        def load(self, _mapping_file: Path) -> SimpleNamespace:
            return SimpleNamespace(
                mappings_by_cve={"CVE-2024-0001": [object()]},
                techniques_by_id={"T1059": object()},
                metadata={
                    "mapping_framework_version": "1.0",
                    "mapping_version": None,
                    "attack_version": "16.1",
                    "domain": "enterprise-attack",
                    "mapping_framework": "curated",
                    "mapping_file_sha256": "abc123",
                    "metadata_format": "vp-curated",
                    "metadata_source": "unit-test",
                    "creation_date": "2026-01-01",
                    "last_update": "2026-01-02",
                    "organization": "Noetheon",
                    "author": "Security",
                    "contact": "security@example.test",
                },
                warnings=["review pending"],
                quality_report={
                    "low_confidence_count": 1,
                    "review_status_counts": {"needs_review": 1},
                    "confidence_counts": {"low": 1},
                    "mapping_type_counts": {"exploitation": 1},
                },
            )

    monkeypatch.setattr(attack_support, "CuratedAttackMappingProvider", _FakeCuratedProvider)

    result = attack_support.validate_attack_inputs(
        attack_source=AttackSource.local_curated.value,
        attack_mapping_file=tmp_path / "mapping.yaml",
        attack_technique_metadata_file=tmp_path / "metadata.json",
        comparison_mapping_file=tmp_path / "comparison.yaml",
    )

    assert result["source"] == "local-curated"
    assert result["mapping_count"] == 1
    assert result["technique_count"] == 1
    assert result["low_confidence_count"] == 1
    assert "Comparison mapping file is only used" in "\n".join(result["warnings"])
    assert "technique metadata is ignored" in "\n".join(result["warnings"])


def test_attack_validation_and_coverage_renderers_cover_quality_branches(
    tmp_path: Path,
) -> None:
    result = {
        "source": "local-curated",
        "mapping_file": str(tmp_path / "mapping.yaml"),
        "technique_metadata_file": None,
        "unique_cves": 1,
        "mapping_count": 1,
        "technique_count": 1,
        "source_version": "1.0",
        "attack_version": "16.1",
        "domain": "enterprise-attack",
        "mapping_file_sha256": "abc123",
        "technique_metadata_file_sha256": None,
        "metadata_format": "vp-curated",
        "stix_spec_version": None,
        "missing_metadata_ids": [],
        "domain_mismatch": False,
        "attack_version_mismatch": False,
        "revoked_or_deprecated_count": 0,
        "warnings": [],
        "quality_report": {"present": True},
        "low_confidence_count": 1,
        "review_status_counts": {"needs_review": 1},
        "confidence_counts": {"low": 1},
        "mapping_type_counts": {"exploitation": 1},
    }

    panel = attack_support.render_attack_validation_panel(result)
    validation_markdown = attack_support.generate_attack_validation_markdown(result)
    assert "Low-confidence mappings: 1" in str(panel.renderable)
    assert "- None" in validation_markdown

    attack_items = [
        AttackData(
            cve_id="CVE-2024-0001",
            mapped=True,
            attack_relevance="Direct",
            attack_techniques=["T1059"],
            attack_tactics=["execution"],
            mapping_types=["exploitation"],
        ),
        AttackData(cve_id="CVE-2024-0002"),
    ]
    summary = AttackSummary(
        mapped_cves=1,
        unmapped_cves=1,
        mapping_type_distribution={"exploitation": 1},
        technique_distribution={"T1059": 1},
        tactic_distribution={"execution": 1},
    )
    metadata = {"source": "local-curated", "mapping_file": "mapping.yaml"}

    table = attack_support.render_attack_coverage_table(attack_items)
    coverage_markdown = attack_support.generate_attack_coverage_markdown(
        input_path="input.csv",
        attack_items=attack_items,
        summary=summary,
        metadata=metadata,
        warnings=["review pending"],
    )

    assert table.row_count == 2
    assert "CVE-2024-0001" in coverage_markdown
    assert "review pending" in coverage_markdown
    assert attack_support.format_distribution({}) == "None"
    assert attack_support.values_mismatch(None, "enterprise-attack") is False
    assert attack_support.values_mismatch(" Enterprise ", "enterprise") is False
    assert attack_support.values_mismatch("mobile", "enterprise") is True


def test_attack_input_helpers_translate_validation_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingLoader:
        def load(self, *_args: object, **_kwargs: object) -> None:
            raise ValueError("bad input file")

        def load_many(self, *_args: object, **_kwargs: object) -> None:
            raise ValueError("bad input specs")

    def fail_validate(*_args: object, **_kwargs: object) -> None:
        raise ValueError("bad attack mapping")

    def fail_load_attack(*_args: object, **_kwargs: object) -> None:
        raise ValueError("bad attack load")

    monkeypatch.setattr(attack_support, "InputLoader", _FailingLoader)
    monkeypatch.setattr(attack_support, "validate_attack_inputs", fail_validate)
    monkeypatch.setattr(attack_support, "load_attack_only", fail_load_attack)
    monkeypatch.setattr(attack_support, "exit_input_validation", _raise_validation)

    with pytest.raises(_ExitSentinel, match="bad attack mapping"):
        attack_support.validate_attack_inputs_or_exit(
            attack_source=AttackSource.local_csv.value,
            attack_mapping_file=Path("mapping.csv"),
            attack_technique_metadata_file=None,
        )
    with pytest.raises(_ExitSentinel, match="bad input file"):
        attack_support.read_input_cves(Path("input.csv"), max_cves=None)
    with pytest.raises(_ExitSentinel, match="bad input specs"):
        attack_support.read_input_cves_from_specs([], max_cves=None)
    with pytest.raises(_ExitSentinel, match="bad attack load"):
        attack_support.load_attack_only_or_exit(
            ["CVE-2024-0001"],
            attack_source=AttackSource.local_csv.value,
            attack_mapping_file=Path("mapping.csv"),
            attack_technique_metadata_file=None,
        )


def test_attack_validate_rejects_disabled_source() -> None:
    with pytest.raises(ValueError, match="require --attack-source"):
        attack_support.validate_attack_inputs(
            attack_source=AttackSource.none.value,
            attack_mapping_file=Path("mapping.csv"),
            attack_technique_metadata_file=None,
        )


def test_doctor_report_uses_runtime_defaults_and_surfaces_degraded_checks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    waiver_file = tmp_path / "waivers.yml"
    mapping_file = tmp_path / "mapping.json"
    metadata_file = tmp_path / "metadata.json"
    for path in (waiver_file, mapping_file, metadata_file):
        path.write_text("{}", encoding="utf-8")

    loaded = SimpleNamespace(
        path=tmp_path / "vuln-prioritizer.yml",
        document=SimpleNamespace(
            defaults=SimpleNamespace(
                waiver_file=str(waiver_file),
                attack_mapping_file=str(mapping_file),
                attack_technique_metadata_file=str(metadata_file),
            )
        ),
    )

    class _FakeFileCache:
        def __init__(self, _cache_dir: Path, _ttl_hours: int) -> None:
            pass

        def inspect_namespace(self, namespace: str) -> dict[str, int]:
            statuses = {
                "nvd": {"file_count": 1, "valid_count": 0, "expired_count": 0, "invalid_count": 1},
                "epss": {"file_count": 1, "valid_count": 0, "expired_count": 1, "invalid_count": 0},
                "kev": {"file_count": 0, "valid_count": 0, "expired_count": 0, "invalid_count": 0},
            }
            return statuses[namespace]

    monkeypatch.setattr(doctor_support, "get_runtime_config", lambda _ctx: loaded)
    monkeypatch.setattr(
        doctor_support,
        "collect_referenced_files",
        lambda _loaded: [("Cache directory", cache_dir), ("Cache directory", cache_dir)],
    )
    monkeypatch.setattr(doctor_support, "FileCache", _FakeFileCache)
    monkeypatch.setattr(doctor_support, "load_waiver_rules", lambda _path: [object()])
    monkeypatch.setattr(
        doctor_support,
        "summarize_waiver_rules",
        lambda _rules: SimpleNamespace(
            total_rules=2,
            active_count=1,
            review_due_count=0,
            expired_count=1,
        ),
    )

    def validate_attack_with_warnings(**_kwargs: object) -> dict[str, object]:
        return {
            "warnings": ["review pending"],
            "unique_cves": 1,
            "mapping_count": 1,
            "technique_count": 1,
        }

    monkeypatch.setattr(doctor_support, "validate_attack_inputs", validate_attack_with_warnings)

    report = doctor_support.build_doctor_report(
        object(),  # type: ignore[arg-type]
        live=False,
        cache_dir=cache_dir,
        cache_ttl_hours=1,
        waiver_file=None,
        offline_kev_file=tmp_path / "kev.json",
        attack_mapping_file=None,
        attack_technique_metadata_file=metadata_file,
    )

    checks = {check.check_id: check for check in report.checks}
    assert checks["cache.nvd"].status == "error"
    assert checks["cache.epss"].status == "degraded"
    assert checks["waiver.health"].status == "error"
    assert checks["attack.validation"].status == "degraded"
    assert checks["path.offline_kev_file"].status == "error"
    assert checks["path.attack_technique_metadata_file"].status == "ok"


def test_doctor_report_records_waiver_and_attack_parse_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    waiver_file = tmp_path / "waivers.yml"
    mapping_file = tmp_path / "mapping.json"
    waiver_file.write_text("broken", encoding="utf-8")
    mapping_file.write_text("broken", encoding="utf-8")

    class _FakeFileCache:
        def __init__(self, _cache_dir: Path, _ttl_hours: int) -> None:
            pass

        def inspect_namespace(self, _namespace: str) -> dict[str, int]:
            return {"file_count": 0, "valid_count": 0, "expired_count": 0, "invalid_count": 0}

    monkeypatch.setattr(doctor_support, "get_runtime_config", lambda _ctx: None)
    monkeypatch.setattr(doctor_support, "FileCache", _FakeFileCache)
    monkeypatch.setattr(
        doctor_support,
        "load_waiver_rules",
        lambda _path: (_ for _ in ()).throw(ValueError("bad waiver file")),
    )
    monkeypatch.setattr(
        doctor_support,
        "validate_attack_inputs",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("bad attack mapping")),
    )

    report = doctor_support.build_doctor_report(
        object(),  # type: ignore[arg-type]
        live=False,
        cache_dir=cache_dir,
        cache_ttl_hours=1,
        waiver_file=waiver_file,
        offline_kev_file=None,
        attack_mapping_file=mapping_file,
        attack_technique_metadata_file=None,
    )

    checks = {check.check_id: check for check in report.checks}
    assert checks["waiver.health"].status == "error"
    assert checks["waiver.health"].detail == "bad waiver file"
    assert checks["attack.validation"].status == "error"
    assert checks["attack.validation"].detail == "bad attack mapping"


def test_doctor_live_probe_exception_and_kev_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_request(*_args: object, **_kwargs: object) -> None:
        raise requests.Timeout("network down")

    monkeypatch.setattr(doctor_support.requests, "get", fail_request)
    failed_probe = doctor_support.probe_live_source("nvd_api", "https://example.test")
    assert failed_probe.status == "error"
    assert "network down" in failed_probe.detail

    primary_error = doctor_support.doctor_check(
        "live.kev_feed",
        name="kev_feed",
        scope="live",
        category="connectivity",
        status="error",
        detail="primary failed",
    )
    mirror_ok = doctor_support.doctor_check(
        "live.kev_mirror",
        name="kev_mirror",
        scope="live",
        category="connectivity",
        status="ok",
        detail="mirror ok",
    )
    probes = iter([primary_error, mirror_ok])
    monkeypatch.setattr(doctor_support, "probe_live_source", lambda *_args, **_kwargs: next(probes))
    fallback = doctor_support.probe_kev_live_source()
    assert fallback.status == "degraded"
    assert "mirror endpoint reachable" in fallback.detail

    mirror_error = doctor_support.doctor_check(
        "live.kev_mirror",
        name="kev_mirror",
        scope="live",
        category="connectivity",
        status="error",
        detail="mirror failed",
    )
    probes = iter([primary_error, mirror_error])
    monkeypatch.setattr(doctor_support, "probe_live_source", lambda *_args, **_kwargs: next(probes))
    failed_fallback = doctor_support.probe_kev_live_source()
    assert failed_fallback.status == "error"
    assert "primary failed / mirror failed" in failed_fallback.detail


def test_doctor_unique_path_entries_keeps_first_duplicate() -> None:
    path = Path("same.yml")

    assert doctor_support.unique_path_entries(
        [("Waiver file", path), ("Waiver file", path), ("Offline KEV file", path)]
    ) == [("Waiver file", path), ("Offline KEV file", path)]
