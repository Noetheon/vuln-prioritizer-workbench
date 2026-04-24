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
    assert "fail-on-provider-error" in inputs
    assert "sort-by" in inputs
    assert "input" in inputs
    assert "input-format" in inputs

    assert "newline-delimited" in inputs["input"]["description"]
    assert "generic-occurrence-csv" in inputs["input-format"]["description"]
    assert "newline-delimited list aligned with input" in inputs["input-format"]["description"]
    assert inputs["locked-provider-data"]["default"] == "false"
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
    assert "cmd+=(--hide-waived)" in script
    assert "cmd+=(--fail-on-provider-error)" in script
    assert '--sort-by "${{ inputs.sort-by }}"' in script
    assert '--max-cves "${{ inputs.max-cves }}"' in script
    assert '--cache-dir "${{ inputs.cache-dir }}"' in script
    assert "report-html mode expects exactly one input path." in script


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
    assert "report html" in script
    assert 'html_report_path="${{ inputs.output-path }}"' in script
