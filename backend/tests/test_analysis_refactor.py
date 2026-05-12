from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vuln_prioritizer.models import (
    PrioritizedFinding,
    PriorityPolicy,
    ProviderDataQualityFlag,
    ProviderLookupDiagnostics,
)
from vuln_prioritizer.options import PriorityFilter
from vuln_prioritizer.services import analysis as service_analysis
from vuln_prioritizer.services import analysis_provider
from vuln_prioritizer.services.analysis_pipeline import (
    _provider_snapshot_hash,
    attach_provider_data_quality_flags,
)


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
    yaml_file = tmp_path / "attack.yml"

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
    assert service_analysis.resolve_attack_options(
        no_attack=False,
        attack_source="none",
        attack_mapping_file=yaml_file,
        attack_technique_metadata_file=json_file,
        offline_attack_file=None,
    ) == (True, "local-curated", yaml_file, None)


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


def test_prepare_saved_explain_reports_json_missing_cve_and_invalid_finding(
    tmp_path: Path,
) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(service_analysis.AnalysisInputError, match="not valid JSON"):
        service_analysis.prepare_saved_explain(
            cve_id="CVE-2024-0001",
            input_path=invalid_json,
            output=None,
            format="json",
        )

    missing_cve = tmp_path / "missing-cve.json"
    missing_cve.write_text(
        json.dumps({"metadata": {}, "findings": [{"cve_id": "CVE-2024-0002"}]}),
        encoding="utf-8",
    )
    with pytest.raises(service_analysis.AnalysisInputError, match="does not contain a finding"):
        service_analysis.prepare_saved_explain(
            cve_id="CVE-2024-0001",
            input_path=missing_cve,
            output=None,
            format="json",
        )

    invalid_finding = tmp_path / "invalid-finding.json"
    invalid_finding.write_text(
        json.dumps({"metadata": {}, "findings": [{"cve_id": "CVE-2024-0001"}]}),
        encoding="utf-8",
    )
    with pytest.raises(service_analysis.AnalysisInputError, match="invalid saved finding"):
        service_analysis.prepare_saved_explain(
            cve_id="CVE-2024-0001",
            input_path=invalid_finding,
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


def test_analysis_requests_require_snapshot_when_provider_data_is_locked(
    tmp_path: Path,
) -> None:
    policy = PriorityPolicy()

    with pytest.raises(service_analysis.AnalysisInputError, match="Locked provider data"):
        service_analysis.prepare_analysis(
            service_analysis.AnalysisRequest(
                input_specs=[],
                output=None,
                format="json",
                provider_snapshot_file=None,
                locked_provider_data=True,
                no_attack=True,
                attack_source="none",
                attack_mapping_file=None,
                attack_technique_metadata_file=None,
                offline_attack_file=None,
                defensive_context_file=None,
                priority_filters=None,
                kev_only=False,
                min_cvss=None,
                min_epss=None,
                sort_by="priority",
                policy=policy,
                policy_profile="default",
                policy_file=None,
                waiver_file=None,
                asset_context=None,
                target_kind="generic",
                target_ref=None,
                vex_files=[],
                show_suppressed=False,
                hide_waived=False,
                fail_on_provider_error=False,
                max_cves=None,
                offline_kev_file=None,
                nvd_api_key_env="NVD_API_KEY",
                no_cache=True,
                cache_dir=tmp_path / "cache",
                cache_ttl_hours=24,
            )
        )

    with pytest.raises(service_analysis.AnalysisInputError, match="Locked provider data"):
        service_analysis.prepare_explain(
            service_analysis.ExplainRequest(
                cve_id="CVE-2024-0001",
                output=None,
                format="json",
                provider_snapshot_file=None,
                locked_provider_data=True,
                no_attack=True,
                attack_source="none",
                attack_mapping_file=None,
                attack_technique_metadata_file=None,
                policy=policy,
                policy_profile="default",
                policy_file=None,
                waiver_file=None,
                asset_context=None,
                target_kind="generic",
                target_ref=None,
                vex_files=[],
                show_suppressed=False,
                fail_on_provider_error=False,
                offline_kev_file=None,
                offline_attack_file=None,
                defensive_context_file=None,
                nvd_api_key_env="NVD_API_KEY",
                no_cache=True,
                cache_dir=tmp_path / "cache",
                cache_ttl_hours=24,
            )
        )

    missing_snapshot = tmp_path / "missing-provider-snapshot.json"
    assert _provider_snapshot_hash(None) is None
    assert _provider_snapshot_hash(missing_snapshot) is None


def test_attach_provider_data_quality_flags_scopes_flags_and_confidence() -> None:
    findings = [
        PrioritizedFinding(
            cve_id="CVE-2026-0701",
            priority_label="Low",
            priority_rank=4,
            rationale="Missing enrichment signals keep this finding low.",
            recommended_action="Review missing data before deferring.",
        ),
        PrioritizedFinding(
            cve_id="CVE-2026-0702",
            priority_label="Low",
            priority_rank=4,
            rationale="No strong exploitation signal.",
            recommended_action="Track in the normal queue.",
        ),
    ]

    enriched = attach_provider_data_quality_flags(
        findings,
        {
            "epss": [
                ProviderDataQualityFlag(
                    source="epss",
                    code="provider_missing_data",
                    message="epss returned no provider content for 1 requested CVE(s).",
                ),
                ProviderDataQualityFlag(
                    source="epss",
                    code="epss_missing",
                    message="FIRST EPSS returned no score for CVE-2026-0701.",
                    cve_id="CVE-2026-0701",
                ),
            ],
            "provider_snapshot": [
                ProviderDataQualityFlag(
                    source="provider_snapshot",
                    code="snapshot_locked",
                    message="Provider snapshot replay is locked.",
                    severity="info",
                )
            ],
        },
    )

    assert [flag.code for flag in enriched[0].data_quality_flags] == [
        "epss_missing",
        "snapshot_locked",
    ]
    assert enriched[0].data_quality_confidence == "medium"
    assert [flag.code for flag in enriched[1].data_quality_flags] == ["snapshot_locked"]
    assert enriched[1].data_quality_confidence == "high"


def test_attach_provider_data_quality_flags_marks_error_confidence_low() -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2026-0703",
        priority_label="Low",
        priority_rank=4,
        rationale="Missing enrichment signals keep this finding low.",
        recommended_action="Review missing data before deferring.",
    )

    enriched = attach_provider_data_quality_flags(
        [finding],
        {
            "kev": [
                ProviderDataQualityFlag(
                    source="kev",
                    code="kev_unavailable",
                    message="CISA KEV catalog was unavailable.",
                    severity="error",
                )
            ]
        },
    )

    assert enriched[0].data_quality_confidence == "low"
    assert [flag.code for flag in enriched[0].data_quality_flags] == ["kev_unavailable"]


def test_attach_provider_data_quality_flags_scopes_provider_errors_by_affected_cve() -> None:
    findings = [
        PrioritizedFinding(
            cve_id="CVE-2026-0704",
            priority_label="Low",
            priority_rank=4,
            rationale="Missing enrichment signals keep this finding low.",
            recommended_action="Review missing data before deferring.",
        ),
        PrioritizedFinding(
            cve_id="CVE-2026-0705",
            priority_label="High",
            priority_rank=2,
            rationale="Provider evidence is complete.",
            recommended_action="Patch normally.",
        ),
    ]

    enriched = attach_provider_data_quality_flags(
        findings,
        {
            "nvd": [
                ProviderDataQualityFlag(
                    source="nvd",
                    code="provider_error",
                    message="nvd provider returned recoverable errors.",
                    severity="error",
                ),
                ProviderDataQualityFlag(
                    source="nvd",
                    code="nvd_missing",
                    message="NVD returned no provider content for CVE-2026-0704.",
                    cve_id="CVE-2026-0704",
                ),
            ]
        },
    )

    assert [flag.code for flag in enriched[0].data_quality_flags] == [
        "provider_error",
        "nvd_missing",
    ]
    assert enriched[0].data_quality_confidence == "low"
    assert enriched[1].data_quality_flags == []
    assert enriched[1].data_quality_confidence == "high"


def test_provider_freshness_helpers_handle_cache_network_and_timestamp_edges() -> None:
    cache_time = "2026-04-24T09:00:00Z"
    lookup_time = "2026-04-24T10:00:00+00:00"

    assert (
        analysis_provider._provider_source_freshness_at(
            diagnostics=ProviderLookupDiagnostics(cache_hits=1),
            cache_timestamp=cache_time,
            lookup_completed_at=lookup_time,
        )
        == cache_time
    )
    assert (
        analysis_provider._provider_source_freshness_at(
            diagnostics=ProviderLookupDiagnostics(stale_cache_hits=1),
            cache_timestamp=cache_time,
            lookup_completed_at=lookup_time,
        )
        == cache_time
    )
    assert (
        analysis_provider._provider_source_freshness_at(
            diagnostics=ProviderLookupDiagnostics(network_fetches=1),
            cache_timestamp=cache_time,
            lookup_completed_at=lookup_time,
        )
        == lookup_time
    )
    assert (
        analysis_provider._provider_source_freshness_at(
            diagnostics=ProviderLookupDiagnostics(empty_records=1),
            cache_timestamp=None,
            lookup_completed_at=lookup_time,
        )
        == lookup_time
    )
    assert (
        analysis_provider._provider_source_freshness_at(
            diagnostics=ProviderLookupDiagnostics(),
            cache_timestamp=cache_time,
            lookup_completed_at=lookup_time,
        )
        == cache_time
    )

    assert analysis_provider._parse_provider_timestamp(None) is None
    assert analysis_provider._parse_provider_timestamp("   ") is None
    assert analysis_provider._parse_provider_timestamp("not-a-date") is None
    assert analysis_provider._parse_provider_timestamp("2026-04-24") == datetime(
        2026, 4, 24, tzinfo=UTC
    )
    assert analysis_provider._parse_provider_timestamp("2026-04-24T09:00:00Z") == datetime(
        2026, 4, 24, 9, tzinfo=UTC
    )
    assert analysis_provider._parse_provider_timestamp("2026-04-24T09:00:00") == datetime(
        2026, 4, 24, 9, tzinfo=UTC
    )
