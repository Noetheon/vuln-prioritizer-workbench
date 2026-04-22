from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.inputs._occurrence_support import apply_asset_context
from vuln_prioritizer.inputs.loader import load_asset_context_file
from vuln_prioritizer.models import InputOccurrence


def _occurrence() -> InputOccurrence:
    return InputOccurrence(
        cve_id="CVE-2024-9999",
        source_format="cve-list",
        target_kind="host",
        target_ref="app-01",
    )


def test_asset_context_legacy_exact_rules_keep_last_row_wins(tmp_path: Path) -> None:
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
    assert catalog.diagnostics.legacy_schema is True
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
    assert diagnostics.glob_rules == 0
    assert diagnostics.legacy_schema is False
