from __future__ import annotations

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackMapping,
    AttackSummary,
    InputSourceSummary,
    PrioritizedFinding,
    ProviderDataQualityFlag,
    ProviderLookupDiagnostics,
    RollupBucket,
    RollupCandidate,
)
from vuln_prioritizer.reporting_format import (
    _attack_methodology_lines,
    _attack_summary_lines,
    _capability_groups,
    _format_attack_indicator,
    _format_distribution,
    _format_exploit_status,
    _format_priority_indicator,
    _format_rollup_candidates,
    _format_rollup_reason,
    _format_state_waiver_status,
    _format_vex_statuses,
    _format_waiver_status,
    _mapping_types,
    _priority_display_label,
    _run_metadata_lines,
    _summary_lines,
    _warning_lines,
    comma_or_na,
    escape_pipes,
    format_change,
    format_data_quality_flags,
    format_filters,
    format_score,
    normalize_whitespace,
    truncate_text,
)


def test_scalar_format_helpers_cover_empty_and_non_empty_values() -> None:
    assert format_score(None, 2) == "N.A."
    assert format_score(0.12345, 2) == "0.12"
    assert format_change(3) == "Up 3"
    assert format_change(-2) == "Down 2"
    assert format_change(0) == "No change"
    assert normalize_whitespace(" first\nsecond\r\n third ") == "first second third"
    assert truncate_text("alpha beta gamma", 11) == "alpha be..."
    assert truncate_text("short", 10) == "short"
    assert escape_pipes(" left | right ") == "left \\| right"
    assert comma_or_na(["one", "two"]) == "one, two"
    assert comma_or_na([]) == "N.A."
    assert format_filters(["kev", "high"]) == "kev, high"
    assert format_filters([]) == "None"


def test_metadata_and_summary_lines_include_optional_workbench_fields() -> None:
    context = AnalysisContext(
        input_path="input-a.txt",
        input_paths=["input-a.txt", "input-b.txt"],
        input_sources=[
            InputSourceSummary(
                input_path="input-a.txt",
                input_format="cve-list",
                total_rows=4,
                occurrence_count=3,
                unique_cves=2,
            )
        ],
        output_path="report.md",
        output_format="markdown",
        generated_at="2026-04-24T10:00:00Z",
        merged_input_count=2,
        duplicate_cve_count=1,
        provider_snapshot_id="snapshot-artifact-1",
        provider_snapshot_hash="f" * 64,
        provider_snapshot_file="snapshot.json",
        locked_provider_data=True,
        provider_snapshot_sources=["nvd", "epss", "kev"],
        provider_freshness={
            "provider_snapshot_generated_at": "2026-04-24T09:00:00Z",
            "nvd_freshness_at": "2026-04-24T09:00:00Z",
            "epss_freshness_at": "2026-04-24T09:00:00Z",
            "kev_freshness_at": "2026-04-24T09:00:00Z",
        },
        attack_enabled=True,
        attack_source="ctid-mappings-explorer",
        attack_mapping_file="attack/mapping.json",
        attack_mapping_file_sha256="a" * 64,
        attack_technique_metadata_file="attack/metadata.json",
        attack_technique_metadata_file_sha256="b" * 64,
        attack_metadata_format="stix-bundle",
        attack_metadata_source="mitre-attack-stix",
        attack_stix_spec_version="2.1",
        mapping_framework="ctid",
        mapping_framework_version="2025.07",
        attack_mapping_created_at="2025-01-01T00:00:00Z",
        attack_mapping_updated_at="2025-02-01T00:00:00Z",
        attack_version="16.1",
        attack_domain="enterprise",
        total_input=4,
        valid_input=2,
        findings_count=2,
        filtered_out_count=1,
        nvd_hits=2,
        epss_hits=1,
        kev_hits=1,
        attack_hits=1,
        nvd_diagnostics=ProviderLookupDiagnostics(
            requested=2,
            cache_hits=1,
            network_fetches=1,
            failures=0,
            content_hits=2,
            empty_records=0,
            stale_cache_hits=0,
        ),
        epss_diagnostics=ProviderLookupDiagnostics(
            requested=2,
            cache_hits=0,
            network_fetches=1,
            failures=1,
            content_hits=1,
            empty_records=1,
            stale_cache_hits=0,
        ),
        kev_diagnostics=ProviderLookupDiagnostics(
            requested=2,
            cache_hits=2,
            network_fetches=0,
            failures=0,
            content_hits=1,
            empty_records=1,
            stale_cache_hits=1,
        ),
        provider_degraded=True,
        provider_data_quality_flags={
            "epss": [
                ProviderDataQualityFlag(
                    source="epss",
                    code="provider_missing_data",
                    message="epss returned no provider content for 1 requested CVE(s).",
                )
            ]
        },
        asset_match_conflict_count=1,
        vex_conflict_count=1,
        waived_count=1,
        waiver_review_due_count=1,
        expired_waiver_count=1,
        active_filters=["priority=high"],
        policy_overrides=["critical-epss=0.500"],
        waiver_file="waivers.yml",
        counts_by_priority={"Critical": 1, "High": 1},
        cache_enabled=True,
        cache_dir=".cache/vuln-prioritizer",
    )

    metadata = "\n".join(_run_metadata_lines(context))
    summary = "\n".join(_summary_lines(context))

    assert "- Provider snapshot mode: `locked`" in metadata
    assert "- Provider snapshot ID: `snapshot-artifact-1`" in metadata
    assert f"- Provider snapshot hash: `{'f' * 64}`" in metadata
    assert "- Provider snapshot generated at: `2026-04-24T09:00:00Z`" in metadata
    assert "- NVD freshness: `2026-04-24T09:00:00Z`" in metadata
    assert "- Inputs merged: `2`" in metadata
    assert "- NVD diagnostics: `requested=2" in metadata
    assert "- EPSS data-quality flags: `provider_missing_data`" in metadata
    assert "- ATT&CK STIX spec version: `2.1`" in metadata
    assert "- Waiver file: `waivers.yml`" in metadata
    assert "- Policy overrides: `critical-epss=0.500`" in metadata
    assert "- Locked provider data: yes" in summary
    assert "- Waiver review due: 1" in summary
    assert "- Critical: 1" in summary
    assert "- Low: 0" in summary
    assert "- Active filters: priority=high" in summary


def test_format_data_quality_flags_deduplicates_codes() -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2026-0801",
        priority_label="Low",
        priority_rank=4,
        rationale="Missing enrichment signals keep this finding low.",
        recommended_action="Review missing data before deferring.",
        data_quality_flags=[
            ProviderDataQualityFlag(
                source="epss",
                code="epss_missing",
                message="FIRST EPSS returned no score.",
            ),
            ProviderDataQualityFlag(
                source="epss",
                code="epss_missing",
                message="Duplicate source flag.",
            ),
            ProviderDataQualityFlag(
                source="provider_snapshot",
                code="snapshot_locked",
                message="Locked replay.",
                severity="info",
            ),
        ],
    )

    assert format_data_quality_flags(finding) == "epss_missing, snapshot_locked"


def test_attack_warning_priority_and_waiver_formatting_helpers() -> None:
    summary = AttackSummary(
        mapped_cves=2,
        unmapped_cves=1,
        mapping_type_distribution={"secondary": 1, "primary": 2},
        technique_distribution={"T1059": 1},
        tactic_distribution={"execution": 1},
    )
    finding = PrioritizedFinding(
        cve_id="CVE-2024-0001",
        priority_label="High",
        priority_rank=2,
        rationale="rationale",
        recommended_action="patch",
        waived=True,
        waiver_status="review_due",
        waiver_owner="team-platform",
        waiver_expires_on="2026-12-31",
        waiver_review_on="2026-06-30",
        waiver_days_remaining=30,
        waiver_scope="service:api",
    )

    assert _attack_methodology_lines(
        AnalysisContext(
            input_path="input.txt",
            output_format="markdown",
            generated_at="2026-04-24T10:00:00Z",
            attack_enabled=False,
        )
    ) == ["- ATT&CK context was disabled for this run."]
    assert "No heuristic" in "\n".join(
        _attack_methodology_lines(
            AnalysisContext(
                input_path="input.txt",
                output_format="markdown",
                generated_at="2026-04-24T10:00:00Z",
                attack_enabled=True,
            )
        )
    )
    assert _attack_summary_lines(summary, enabled=False) == [
        "ATT&CK context was disabled for this export."
    ]
    assert "- Mapping type distribution: primary: 2, secondary: 1" in _attack_summary_lines(
        summary,
        enabled=True,
    )
    assert _warning_lines(["one"]) == ["- one"]
    assert _warning_lines([]) == ["- None"]
    assert _format_distribution({}) == "None"
    assert _format_attack_indicator(False, 0) == "Unmapped"
    assert _format_attack_indicator(True, 2) == "2 technique(s)"
    assert _format_priority_indicator("High", False, in_kev=False) == "High"
    assert (
        _format_priority_indicator("Critical", True, in_kev=True, waiver_status="expired")
        == "Critical (KEV, suppressed, waiver expired)"
    )
    assert (
        _format_priority_indicator("High", False, in_kev=False, waiver_status="review_due")
        == "High (waiver review due)"
    )
    assert _format_priority_indicator("Medium", False, in_kev=False, waived=True) == (
        "Medium (waived)"
    )
    assert _priority_display_label("Critical", True, waiver_status="expired") == (
        "Critical / KEV / Waiver Expired"
    )
    assert _priority_display_label("High", False, waiver_status="review_due") == (
        "High / Waiver Review Due"
    )
    assert _priority_display_label("Medium", False, waived=True) == "Medium / Waived"
    assert _format_exploit_status(True) == "Known exploited (KEV)"
    assert _format_exploit_status(False) == "No KEV listing"
    assert _format_vex_statuses({}) == "N.A."
    assert _format_vex_statuses({"affected": 2}) == "affected: 2"
    assert _format_waiver_status(finding) == (
        "status=review_due, owner=team-platform, expires=2026-12-31, "
        "review_on=2026-06-30, days_remaining=30, scope=service:api"
    )
    assert (
        _format_waiver_status(
            PrioritizedFinding(
                cve_id="CVE-2024-0002",
                priority_label="Low",
                priority_rank=4,
                rationale="rationale",
                recommended_action="monitor",
            )
        )
        == "N.A."
    )


def test_mapping_and_rollup_formatting_helpers() -> None:
    mappings = [
        AttackMapping(
            capability_id="CVE-2024-0001",
            attack_object_id="T1190",
            mapping_type="exploitation",
            capability_group="public-app",
        ),
        AttackMapping(
            capability_id="CVE-2024-0001",
            attack_object_id="T1059",
            mapping_type="exploitation",
            capability_group="execution",
        ),
    ]
    bucket = RollupBucket(
        bucket="service:api",
        dimension="service",
        actionable_count=2,
        kev_count=1,
        internet_facing_count=1,
        production_count=1,
        waived_count=1,
        highest_priority="Critical",
        context_hints=["owner team-platform"],
    )

    assert _mapping_types(mappings) == ["exploitation"]
    assert _capability_groups(mappings) == ["public-app", "execution"]
    assert _format_rollup_candidates([]) == "N.A."
    assert (
        _format_rollup_candidates(
            [
                RollupCandidate(
                    cve_id="CVE-2024-0001",
                    priority_label="Critical",
                    recommended_action="patch",
                    rank_reason="Critical + KEV",
                )
            ]
        )
        == "CVE-2024-0001 (Critical + KEV)"
    )
    assert _format_rollup_reason(bucket) == (
        "Critical + KEV + internet-facing + prod + 1 waived (owner team-platform)"
    )
    assert (
        _format_rollup_reason(
            RollupBucket(
                bucket="service:legacy",
                dimension="service",
                actionable_count=0,
                highest_priority="Low",
            )
        )
        == "All findings waived"
    )
    assert _format_state_waiver_status(False, None) == "No"
    assert _format_state_waiver_status(True, None) == "active"
    assert _format_state_waiver_status(True, "expired") == "expired"
