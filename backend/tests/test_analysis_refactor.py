from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer

from vuln_prioritizer.cli_support import analysis as cli_analysis
from vuln_prioritizer.cli_support.common import PriorityFilter
from vuln_prioritizer.models import AnalysisContext, PrioritizedFinding, PriorityPolicy
from vuln_prioritizer.services import analysis as service_analysis


def test_analysis_service_rejects_invalid_policy_thresholds() -> None:
    with pytest.raises(service_analysis.AnalysisInputError):
        service_analysis.build_priority_policy(
            critical_epss_threshold=1.5,
            critical_cvss_threshold=7.0,
            high_epss_threshold=0.4,
            high_cvss_threshold=9.0,
            medium_epss_threshold=0.1,
            medium_cvss_threshold=7.0,
        )


def test_analysis_service_resolves_attack_option_modes(tmp_path: Path) -> None:
    csv_file = tmp_path / "attack.csv"
    json_file = tmp_path / "attack.json"

    assert service_analysis.resolve_attack_options(
        no_attack=True,
        attack_source="ctid-json",
        attack_mapping_file=json_file,
        attack_technique_metadata_file=None,
        offline_attack_file=None,
    ) == (False, "none", None, None)
    assert service_analysis.resolve_attack_options(
        no_attack=False,
        attack_source="none",
        attack_mapping_file=None,
        attack_technique_metadata_file=None,
        offline_attack_file=csv_file,
    ) == (True, "local-csv", csv_file, None)
    assert service_analysis.resolve_attack_options(
        no_attack=False,
        attack_source="none",
        attack_mapping_file=json_file,
        attack_technique_metadata_file=None,
        offline_attack_file=None,
    ) == (True, "ctid-json", json_file, None)


def test_analysis_service_filter_helpers_accept_enum_and_string_values() -> None:
    filters = service_analysis.normalize_priority_filters([PriorityFilter.critical, "high"])

    assert filters == {"Critical", "High"}
    assert service_analysis.build_active_filters(
        priority_filters=[PriorityFilter.critical, "high"],
        kev_only=True,
        min_cvss=7.0,
        min_epss=0.2,
        show_suppressed=True,
        hide_waived=True,
    ) == [
        "priority=Critical,High",
        "kev-only",
        "min-cvss>=7.0",
        "min-epss>=0.200",
        "show-suppressed",
        "hide-waived",
    ]


def test_analysis_service_requires_attack_mapping_file_for_enabled_mode() -> None:
    with pytest.raises(service_analysis.AnalysisInputError):
        service_analysis.validate_requested_attack_mode(
            attack_enabled=True,
            attack_source="ctid-json",
            attack_mapping_file=None,
            offline_attack_file=None,
        )


def test_prepare_saved_explain_reports_invalid_saved_payload(tmp_path: Path) -> None:
    saved = tmp_path / "analysis.json"
    saved.write_text(json.dumps({"metadata": {}}), encoding="utf-8")

    with pytest.raises(service_analysis.AnalysisInputError):
        service_analysis.prepare_saved_explain(
            cve_id="CVE-2024-0001",
            input_path=saved,
            output=None,
            format="json",
        )


def test_prepare_saved_explain_builds_result_from_saved_payload(tmp_path: Path) -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2024-0001",
        priority_label="Low",
        priority_rank=4,
        rationale="No strong exploitation signal.",
        recommended_action="Track in the normal queue.",
    )
    saved = tmp_path / "analysis.json"
    saved.write_text(
        json.dumps(
            {
                "metadata": {
                    "input_path": "input.txt",
                    "output_format": "json",
                    "generated_at": "2026-04-25T00:00:00+00:00",
                    "total_input": 1,
                    "valid_input": 1,
                    "findings_count": 1,
                    "filtered_out_count": 0,
                    "nvd_hits": 0,
                    "epss_hits": 0,
                    "kev_hits": 0,
                    "priority_policy": PriorityPolicy().model_dump(),
                },
                "attack_summary": {},
                "findings": [finding.model_dump()],
            }
        ),
        encoding="utf-8",
    )

    result = service_analysis.prepare_saved_explain(
        cve_id="CVE-2024-0001",
        input_path=saved,
        output=None,
        format="json",
    )

    assert result.finding.cve_id == "CVE-2024-0001"
    assert result.context.input_path == str(saved)


@pytest.mark.parametrize(
    ("wrapper_name", "target_name"),
    [
        ("build_priority_policy", "_build_priority_policy"),
        ("load_asset_records_or_exit", "_load_asset_records"),
        ("load_vex_statements_or_exit", "_load_vex_statements"),
        ("load_waiver_rules_or_exit", "_load_waiver_rules"),
        ("load_context_profile_or_exit", "_load_context_profile"),
        ("load_provider_snapshot_or_exit", "_load_provider_snapshot"),
        ("build_findings", "_build_findings"),
        ("prepare_saved_explain", "_prepare_saved_explain"),
    ],
)
def test_cli_analysis_facade_translates_input_errors(
    monkeypatch: pytest.MonkeyPatch,
    wrapper_name: str,
    target_name: str,
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise service_analysis.AnalysisInputError("bad input")

    monkeypatch.setattr(cli_analysis, target_name, fail)

    with pytest.raises(typer.Exit) as exc_info:
        getattr(cli_analysis, wrapper_name)()

    assert exc_info.value.exit_code == 2


def test_cli_analysis_facade_translates_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(request: object) -> None:
        raise service_analysis.AnalysisNoFindingsError("nothing")

    monkeypatch.setattr(cli_analysis, "_prepare_analysis", fail)

    with pytest.raises(typer.Exit) as exc_info:
        cli_analysis.prepare_analysis(object())  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 1


def test_cli_fail_handlers_raise_expected_exit_codes() -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2024-0001",
        priority_label="High",
        priority_rank=2,
        rationale="High priority.",
        recommended_action="Patch.",
    )
    context = AnalysisContext(
        input_path="input.txt",
        output_format="json",
        generated_at="2026-04-25T00:00:00+00:00",
        total_input=1,
        valid_input=1,
        findings_count=1,
        filtered_out_count=0,
        nvd_hits=0,
        epss_hits=0,
        kev_hits=0,
        provider_degraded=True,
        expired_waiver_count=1,
    )

    with pytest.raises(typer.Exit):
        cli_analysis.handle_fail_on([finding], PriorityFilter.high)
    with pytest.raises(typer.Exit):
        cli_analysis.handle_provider_error_fail_on(context, fail_on_provider_error=True)
    with pytest.raises(typer.Exit):
        cli_analysis.handle_waiver_lifecycle_fail_on(
            context,
            fail_on_expired_waivers=True,
            fail_on_review_due_waivers=False,
        )
