from __future__ import annotations

from pathlib import Path

import yaml


def _load_action_definition() -> dict[str, object]:
    return yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))


def test_action_exposes_p1_analyze_inputs() -> None:
    action = _load_action_definition()
    inputs = action["inputs"]

    assert "provider-snapshot-file" in inputs
    assert "locked-provider-data" in inputs
    assert "waiver-file" in inputs
    assert "defensive-context-file" in inputs
    assert "validate-sarif" in inputs
    assert "fail-on-provider-error" in inputs
    assert "sort-by" in inputs
    assert "input" in inputs
    assert "input-format" in inputs
    assert "cve" in inputs
    assert "max-provider-age-hours" in inputs
    assert "fail-on-stale-provider-data" in inputs
    assert "rollup-by" in inputs
    assert "rollup-top" in inputs

    assert "newline-delimited" in inputs["input"]["description"]
    assert inputs["input"]["required"] is False
    assert "compare" in inputs["mode"]["description"]
    assert "input-validate" in inputs["mode"]["description"]
    assert "attack-coverage" in inputs["mode"]["description"]
    assert "workbench-report" in inputs["mode"]["description"]
    assert "validate-sarif" in inputs["mode"]["description"]
    assert (
        "SARIF file" in inputs["input"]["description"] or "SARIF" in inputs["input"]["description"]
    )
    assert "validate-sarif mode" in inputs["output-path"]["description"]
    assert "validate-sarif mode" in action["outputs"]["sarif-validation-path"]["description"]
    assert "generic-occurrence-csv" in inputs["input-format"]["description"]
    assert "newline-delimited list aligned with input" in inputs["input-format"]["description"]
    assert "workbench-report mode" in inputs["output-format"]["description"]
    assert inputs["locked-provider-data"]["default"] == "false"
    assert inputs["validate-sarif"]["default"] == "false"
    assert inputs["fail-on-stale-provider-data"]["default"] == "false"
    assert "operational" in inputs["sort-by"]["description"]


def test_action_run_step_supports_multiline_inputs_and_snapshot_replay() -> None:
    action = _load_action_definition()
    run_step = action["runs"]["steps"][-1]
    script = run_step["run"]

    assert "count_nonempty_lines()" in script
    assert 'append_multiline_args "--input" "${{ inputs.input }}"' in script
    assert 'append_multiline_args "--input-format" "${{ inputs.input-format }}"' in script
    assert 'append_multiline_args "--vex-file" "${{ inputs.vex-files }}"' in script
    assert '--provider-snapshot-file "${{ inputs.provider-snapshot-file }}"' in script
    assert "cmd+=(--locked-provider-data)" in script
    assert '--waiver-file "${{ inputs.waiver-file }}"' in script
    assert '--defensive-context-file "${{ inputs.defensive-context-file }}"' in script
    assert "cmd+=(--hide-waived)" in script
    assert "cmd+=(--fail-on-provider-error)" in script
    assert '--max-provider-age-hours "${{ inputs.max-provider-age-hours }}"' in script
    assert "cmd+=(--fail-on-stale-provider-data)" in script
    assert '--sort-by "${{ inputs.sort-by }}"' in script
    assert '--max-cves "${{ inputs.max-cves }}"' in script
    assert '--cache-dir "${{ inputs.cache-dir }}"' in script
    assert "$mode mode expects exactly one input path." in script
    assert '"$mode" == "compare"' in script
    assert "compare" in script
    assert '"$mode" == "explain"' in script
    assert '--cve "${{ inputs.cve }}"' in script
    assert '"$mode" == "doctor"' in script
    assert "doctor" in script
    assert '"$mode" == "input-validate"' in script
    assert "input validate" in script
    assert '"$mode" == "snapshot"' in script
    assert "snapshot create" in script
    assert '"$mode" == "rollup"' in script
    assert '--by "${{ inputs.rollup-by }}"' in script
    assert '"$mode" == "data-verify"' in script
    assert "data verify" in script
    assert '"$mode" == "attack-validate"' in script
    assert "attack validate" in script
    assert '"$mode" == "attack-coverage"' in script
    assert "attack coverage" in script
    assert "workbench-report" in script
    assert "report workbench" in script
    assert "report evidence-bundle" in script
    assert "report verify-evidence-bundle" in script
    assert '"$mode" == "validate-sarif"' in script
    assert "report validate-sarif" in script
    assert 'sarif_validation_path="${{ inputs.output-path }}"' in script


def test_action_run_step_wires_step_summary_outputs_and_report_html_mode() -> None:
    action = _load_action_definition()
    run_step = action["runs"]["steps"][-1]
    script = run_step["run"]

    assert 'cmd+=(--summary-output "$requested_summary_path")' in script
    assert 'cmd+=(--summary-template "$summary_template")' in script
    assert 'cat "$summary_path" >> "$GITHUB_STEP_SUMMARY"' in script
    assert 'echo "report-path=${{ inputs.output-path }}" >> "$GITHUB_OUTPUT"' in script
    assert 'echo "html-report-path=$html_report_path" >> "$GITHUB_OUTPUT"' in script
    assert 'echo "summary-path=$summary_path" >> "$GITHUB_OUTPUT"' in script
    assert 'echo "sarif-validation-path=$sarif_validation_path" >> "$GITHUB_OUTPUT"' in script
    assert "report html" in script
    assert 'html_report_path="${{ inputs.output-path }}"' in script
    assert "report validate-sarif" in script
    assert (
        'if [[ "${{ inputs.validate-sarif }}" == "true" && "$mode" != "validate-sarif" ]]; then'
        in script
    )
    assert 'sarif_report_path="${{ inputs.output-path }}"' in script
    assert (
        "validate-sarif requires mode=analyze or mode=workbench-report with output-format=sarif."
        in script
    )
    assert '--input "$sarif_report_path"' in script
