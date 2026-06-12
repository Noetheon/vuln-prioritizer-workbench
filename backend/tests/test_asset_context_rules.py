from __future__ import annotations

from pathlib import Path

import pytest

from app.domain.engine.inputs._occurrence_support import apply_asset_context
from app.domain.engine.inputs.loader import load_asset_context_file
from app.domain.engine.models import InputOccurrence, PrioritizedFinding
from app.domain.engine.services.contextualization import aggregate_provenance
from app.domain.engine.services.prioritization import PrioritizationService


def _occurrence() -> InputOccurrence:
    return InputOccurrence(
        cve_id="CVE-2024-9999",
        source_format="cve-list",
        target_kind="host",
        target_ref="app-01",
    )


def test_asset_context_basic_exact_rules_keep_last_row_wins(tmp_path: Path) -> None:
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality",
                "host,app-01,asset-old,low",
                "host,app-01,asset-new,high",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    catalog = load_asset_context_file(asset_context_file)
    resolved = apply_asset_context([_occurrence()], catalog)

    assert resolved[0].asset_id == "asset-new"
    assert resolved[0].asset_criticality == "high"
    assert catalog.diagnostics.basic_schema is True
    assert catalog.diagnostics.glob_rules == 0


def test_asset_context_exact_rule_beats_glob_when_precedence_ties(tmp_path: Path) -> None:
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "rule_id,target_kind,target_ref,asset_id,match_mode,precedence",
                "glob-rule,host,app-*,asset-glob,glob,20",
                "exact-rule,host,app-01,asset-exact,exact,20",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    catalog = load_asset_context_file(asset_context_file)
    resolved, diagnostics = apply_asset_context([_occurrence()], catalog, return_diagnostics=True)

    assert resolved[0].asset_id == "asset-exact"
    assert resolved[0].asset_match_rule_id == "exact-rule"
    assert resolved[0].asset_match_candidate_count == 2
    assert diagnostics.matched_occurrences == 1
    assert diagnostics.exact_matches == 1
    assert diagnostics.glob_matches == 0
    assert diagnostics.ambiguous_occurrences == 1
    assert diagnostics.warnings


def test_asset_context_higher_precedence_wins_and_returns_load_diagnostics(
    tmp_path: Path,
) -> None:
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "rule_id,target_kind,target_ref,asset_id,match_mode,precedence",
                "low-rule,host,app-01,asset-low,exact,1",
                "high-rule,host,app-01,asset-high,exact,50",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    catalog, diagnostics = load_asset_context_file(
        asset_context_file,
        return_diagnostics=True,
    )
    resolved = apply_asset_context([_occurrence()], catalog)

    assert resolved[0].asset_id == "asset-high"
    assert diagnostics.total_rows == 2
    assert diagnostics.loaded_rows == 2
    assert diagnostics.exact_rules == 2
    assert diagnostics.contains_rules == 0
    assert diagnostics.regex_rules == 0
    assert diagnostics.glob_rules == 0
    assert diagnostics.basic_schema is False


def test_asset_context_contains_rule_matches_target_ref_and_reports_invalid_enums(
    tmp_path: Path,
) -> None:
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                ",".join(
                    [
                        "rule_id",
                        "target_kind",
                        "target_ref",
                        "asset_id",
                        "match_mode",
                        "precedence",
                        "criticality",
                        "exposure",
                        "environment",
                        "owner",
                        "business_service",
                    ]
                ),
                ",".join(
                    [
                        "contains-rule",
                        "host",
                        "app-",
                        "asset-contains",
                        "contains",
                        "10",
                        "tier-0",
                        "publicly",
                        "productionish",
                        "platform-team",
                        "checkout",
                    ]
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    catalog, diagnostics = load_asset_context_file(asset_context_file, return_diagnostics=True)
    resolved, match_diagnostics = apply_asset_context(
        [_occurrence()],
        catalog,
        return_diagnostics=True,
    )

    assert resolved[0].asset_id == "asset-contains"
    assert resolved[0].asset_match_mode == "contains"
    assert resolved[0].asset_owner == "platform-team"
    assert resolved[0].asset_business_service == "checkout"
    assert resolved[0].asset_criticality is None
    assert resolved[0].asset_exposure is None
    assert resolved[0].asset_environment is None
    assert diagnostics.loaded_rows == 1
    assert diagnostics.contains_rules == 1
    assert diagnostics.regex_rules == 0
    assert diagnostics.exact_rules == 0
    assert diagnostics.glob_rules == 0
    assert any("unknown asset criticality" in warning for warning in diagnostics.warnings)
    assert any("unknown asset exposure" in warning for warning in diagnostics.warnings)
    assert any("unknown asset environment" in warning for warning in diagnostics.warnings)
    assert match_diagnostics.contains_matches == 1
    assert match_diagnostics.regex_matches == 0
    assert match_diagnostics.exact_matches == 0


def test_asset_context_regex_rule_matches_and_loses_to_exact_on_tied_precedence(
    tmp_path: Path,
) -> None:
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "rule_id,target_kind,target_ref,asset_id,match_mode,precedence",
                "regex-rule,host,^app-[0-9]{2}$,asset-regex,regex,20",
                "exact-rule,host,app-01,asset-exact,exact,20",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    catalog, diagnostics = load_asset_context_file(asset_context_file, return_diagnostics=True)
    resolved, match_diagnostics = apply_asset_context(
        [_occurrence()],
        catalog,
        return_diagnostics=True,
    )

    assert resolved[0].asset_id == "asset-exact"
    assert resolved[0].asset_match_rule_id == "exact-rule"
    assert resolved[0].asset_match_candidate_count == 2
    assert diagnostics.regex_rules == 1
    assert diagnostics.exact_rules == 1
    assert match_diagnostics.exact_matches == 1
    assert match_diagnostics.regex_matches == 0
    assert match_diagnostics.ambiguous_occurrences == 1


def test_asset_context_invalid_regex_reports_row_number(tmp_path: Path) -> None:
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "rule_id,target_kind,target_ref,asset_id,match_mode,precedence",
                "broken-regex,host,[app,asset-regex,regex,20",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    try:
        load_asset_context_file(asset_context_file)
    except ValueError as exc:
        assert "regex at row 1 is invalid" in str(exc)
    else:  # pragma: no cover - defensive assertion for clearer failure output
        raise AssertionError("invalid regex should raise ValueError")


def test_asset_context_unsafe_regex_reports_row_number(tmp_path: Path) -> None:
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "rule_id,target_kind,target_ref,asset_id,match_mode,precedence",
                "unsafe-regex,host,^(a+)+$,asset-regex,regex,20",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="regex at row 1 is unsafe"):
        load_asset_context_file(asset_context_file)


def test_asset_context_application_recomputes_operational_score(
    tmp_path: Path,
) -> None:
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                ",".join(
                    [
                        "rule_id",
                        "target_kind",
                        "target_ref",
                        "asset_id",
                        "match_mode",
                        "precedence",
                        "criticality",
                        "exposure",
                        "environment",
                        "owner",
                        "business_service",
                    ]
                ),
                ",".join(
                    [
                        "prod-api",
                        "host",
                        "app-01",
                        "asset-prod-api",
                        "exact",
                        "10",
                        "critical",
                        "internet-facing",
                        "prod",
                        "platform-team",
                        "checkout",
                    ]
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    catalog = load_asset_context_file(asset_context_file)
    enriched_occurrences = apply_asset_context([_occurrence()], catalog)
    provenance = aggregate_provenance(["CVE-2024-9999"], enriched_occurrences)["CVE-2024-9999"]
    finding = PrioritizedFinding(
        cve_id="CVE-2024-9999",
        priority_label="High",
        priority_rank=2,
        priority_drivers=["medium-cvss"],
        cvss_base_score=8.0,
        epss=0.05,
        rationale="fixture finding",
        recommended_action="patch",
        provenance=provenance,
        highest_asset_criticality=provenance.highest_asset_criticality,
        asset_count=provenance.asset_count,
    )

    scored = PrioritizationService().assign_operational_ranks([finding])[0]

    assert scored.priority_label == "High"
    assert scored.operational_score == 61
    assert "internet-facing asset context: +8" in scored.operational_score_reasons
    assert "production asset context: +4" in scored.operational_score_reasons
    assert "critical asset criticality: +7" in scored.operational_score_reasons
    assert "business service checkout routing context: +0" in scored.operational_score_reasons
    assert "owner platform-team routing context: +0" in scored.operational_score_reasons
