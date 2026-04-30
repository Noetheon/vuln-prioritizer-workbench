from __future__ import annotations

import yaml
from paths import REPO_ROOT

ACTION_FILE = REPO_ROOT / "action.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
EXAMPLES_DIR = REPO_ROOT / ".github" / "examples"
EXAMPLES_README = EXAMPLES_DIR / "README.md"
INTEGRATION_DOC = REPO_ROOT / "docs" / "integrations" / "reporting_and_ci.md"
README_FILE = REPO_ROOT / "README.md"
MKDOCS_FILE = REPO_ROOT / "mkdocs.yml"
VPW_082_EVIDENCE = REPO_ROOT / "docs" / "evidence" / "vpw-082-github-action-reports.md"
SARIF_EXAMPLE = EXAMPLES_DIR / "code-scanning-sarif.yml"
WORKBENCH_REPORT_EXAMPLE = EXAMPLES_DIR / "workbench-report-artifacts.yml"


def _load_action_definition() -> dict[str, object]:
    return yaml.safe_load(ACTION_FILE.read_text(encoding="utf-8"))


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
    env = run_step["env"]

    assert env["INPUT_MODE"] == "${{ inputs.mode }}"
    assert env["INPUT_INPUT"] == "${{ inputs.input }}"
    assert env["INPUT_OUTPUT_PATH"] == "${{ inputs.output-path }}"
    assert "${{ inputs." not in script
    assert "count_nonempty_lines()" in script
    assert 'append_multiline_args "--input" "$INPUT_INPUT"' in script
    assert 'append_multiline_args "--input-format" "$INPUT_INPUT_FORMAT"' in script
    assert 'append_multiline_args "--vex-file" "$INPUT_VEX_FILES"' in script
    assert '--provider-snapshot-file "$INPUT_PROVIDER_SNAPSHOT_FILE"' in script
    assert "cmd+=(--locked-provider-data)" in script
    assert '--waiver-file "$INPUT_WAIVER_FILE"' in script
    assert '--defensive-context-file "$INPUT_DEFENSIVE_CONTEXT_FILE"' in script
    assert "cmd+=(--hide-waived)" in script
    assert "cmd+=(--fail-on-provider-error)" in script
    assert '--max-provider-age-hours "$INPUT_MAX_PROVIDER_AGE_HOURS"' in script
    assert "cmd+=(--fail-on-stale-provider-data)" in script
    assert '--sort-by "$INPUT_SORT_BY"' in script
    assert '--max-cves "$INPUT_MAX_CVES"' in script
    assert '--cache-dir "$INPUT_CACHE_DIR"' in script
    assert "$mode mode expects exactly one input path." in script
    assert '"$mode" == "compare"' in script
    assert "compare" in script
    assert '"$mode" == "explain"' in script
    assert '--cve "$INPUT_CVE"' in script
    assert '"$mode" == "doctor"' in script
    assert "doctor" in script
    assert '"$mode" == "input-validate"' in script
    assert "input validate" in script
    assert '"$mode" == "snapshot"' in script
    assert "snapshot create" in script
    assert '"$mode" == "rollup"' in script
    assert '--by "$INPUT_ROLLUP_BY"' in script
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
    assert 'sarif_validation_path="$INPUT_OUTPUT_PATH"' in script


def test_action_run_step_wires_step_summary_outputs_and_report_html_mode() -> None:
    action = _load_action_definition()
    run_step = action["runs"]["steps"][-1]
    script = run_step["run"]

    assert 'cmd+=(--summary-output "$requested_summary_path")' in script
    assert 'cmd+=(--summary-template "$summary_template")' in script
    assert 'cat "$summary_path" >> "$GITHUB_STEP_SUMMARY"' in script
    assert "write_action_output()" in script
    assert 'write_action_output "report-path" "$INPUT_OUTPUT_PATH"' in script
    assert 'write_action_output "html-report-path" "$html_report_path"' in script
    assert 'write_action_output "summary-path" "$summary_path"' in script
    assert 'write_action_output "sarif-validation-path" "$sarif_validation_path"' in script
    assert 'printf \'%s<<%s\\n\' "$name" "$delimiter"' in script
    assert "report html" in script
    assert 'html_report_path="$INPUT_OUTPUT_PATH"' in script
    assert "report validate-sarif" in script
    assert (
        'if [[ "$INPUT_VALIDATE_SARIF" == "true" && "$mode" != "validate-sarif" ]]; then' in script
    )
    assert 'sarif_report_path="$INPUT_OUTPUT_PATH"' in script
    assert (
        "validate-sarif requires mode=analyze or mode=workbench-report with output-format=sarif."
        in script
    )
    assert '--input "$sarif_report_path"' in script


def test_action_shell_steps_do_not_interpolate_inputs_directly() -> None:
    action = _load_action_definition()
    run_steps = [step for step in action["runs"]["steps"] if "run" in step]

    assert run_steps
    for step in run_steps:
        assert "${{ inputs." not in step["run"]


def test_action_installs_backend_package_from_composite_checkout() -> None:
    action = _load_action_definition()
    install_step = action["runs"]["steps"][1]

    assert install_step["name"] == "Install vuln-prioritizer from action checkout"
    assert 'python -m pip install "${{ github.action_path }}/backend"' in install_step["run"]


def test_vpw082_workbench_report_example_generates_markdown_and_json_secretless() -> None:
    raw = WORKBENCH_REPORT_EXAMPLE.read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw)
    steps = workflow["jobs"]["reports"]["steps"]
    steps_by_id = {step["id"]: step for step in steps if "id" in step}
    upload_step = next(step for step in steps if step.get("uses") == "actions/upload-artifact@v7")

    assert workflow["permissions"] == {"contents": "read"}
    assert "secrets." not in raw
    assert "nvd-api-key-env" not in raw

    analyze = steps_by_id["analyze"]
    assert analyze["uses"] == "Noetheon/vuln-prioritizer-workbench@vX.Y.Z"
    assert analyze["with"] == {
        "mode": "analyze",
        "input": "trivy-results.json",
        "input-format": "trivy-json",
        "output-format": "json",
        "output-path": "analysis.json",
        "provider-snapshot-file": "provider-snapshot.json",
        "locked-provider-data": "true",
        "summary-output-path": "summary.md",
        "summary-template": "compact",
        "github-step-summary": "true",
    }

    markdown_report = steps_by_id["markdown-report"]
    json_report = steps_by_id["json-report"]
    for step in (markdown_report, json_report):
        assert step["uses"] == "Noetheon/vuln-prioritizer-workbench@vX.Y.Z"
        assert step["with"]["mode"] == "workbench-report"
        assert step["with"]["input"] == "${{ steps.analyze.outputs.report-path }}"

    assert markdown_report["with"]["output-format"] == "markdown"
    assert markdown_report["with"]["output-path"] == "workbench-report.md"
    assert json_report["with"]["output-format"] == "json"
    assert json_report["with"]["output-path"] == "workbench-report.json"
    assert upload_step["with"]["name"] == "vuln-prioritization-workbench-reports"
    upload_paths = upload_step["with"]["path"]
    assert "${{ steps.markdown-report.outputs.report-path }}" in upload_paths
    assert "${{ steps.json-report.outputs.report-path }}" in upload_paths
    assert "${{ steps.analyze.outputs.summary-path }}" in upload_paths


def test_vpw082_sarif_example_validates_before_upload() -> None:
    workflow = yaml.safe_load(SARIF_EXAMPLE.read_text(encoding="utf-8"))
    prioritize_step = next(
        step for step in workflow["jobs"]["prioritize"]["steps"] if step.get("id") == "prioritize"
    )
    upload_step = next(
        step
        for step in workflow["jobs"]["prioritize"]["steps"]
        if step.get("uses") == "github/codeql-action/upload-sarif@v4"
    )

    assert prioritize_step["with"]["output-format"] == "sarif"
    assert prioritize_step["with"]["validate-sarif"] == "true"
    assert upload_step["with"]["sarif_file"] == "${{ steps.prioritize.outputs.report-path }}"


def test_vpw082_ci_action_smoke_runs_local_action_and_uploads_artifacts() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["action-smoke"]
    steps = job["steps"]
    steps_by_id = {step["id"]: step for step in steps if "id" in step}
    upload_step = next(
        step for step in steps if step.get("name") == "Upload VPW-082 action smoke artifacts"
    )

    assert job["runs-on"] == "ubuntu-latest"

    local_action_steps = [step for step in steps if step.get("uses") == "./"]
    assert [step["id"] for step in local_action_steps] == [
        "analyze",
        "markdown-report",
        "json-report",
    ]

    analyze = steps_by_id["analyze"]
    assert analyze["with"]["mode"] == "analyze"
    assert analyze["with"]["input"] == "data/input_fixtures/trivy_report.json"
    assert analyze["with"]["input-format"] == "trivy-json"
    assert analyze["with"]["output-format"] == "json"
    assert analyze["with"]["provider-snapshot-file"] == "data/demo_provider_snapshot.json"
    assert analyze["with"]["locked-provider-data"] == "true"
    assert analyze["with"]["github-step-summary"] == "true"

    markdown_report = steps_by_id["markdown-report"]
    json_report = steps_by_id["json-report"]
    for step in (markdown_report, json_report):
        assert step["with"]["mode"] == "workbench-report"
        assert step["with"]["input"] == "${{ steps.analyze.outputs.report-path }}"
    assert markdown_report["with"]["output-format"] == "markdown"
    assert json_report["with"]["output-format"] == "json"

    verify_step = next(
        step for step in steps if step.get("name") == "Verify action smoke artifacts"
    )
    verify_script = verify_step["run"]
    assert "test -s build/vpw-082-action-smoke/analysis.json" in verify_script
    assert "test -s build/vpw-082-action-smoke/workbench-report.md" in verify_script
    assert "test -s build/vpw-082-action-smoke/workbench-report.json" in verify_script
    assert 'analysis["metadata"]["locked_provider_data"] is True' in verify_script
    assert (
        'analysis["metadata"]["provider_snapshot_file"] == "data/demo_provider_snapshot.json"'
        in verify_script
    )
    assert 'report["metadata"]["output_format"] == "json"' in verify_script

    assert upload_step["uses"] == "actions/upload-artifact@v7"
    assert upload_step["with"]["name"] == "vpw-082-action-smoke-reports"
    assert "build/vpw-082-action-smoke/workbench-report.md" in upload_step["with"]["path"]
    assert "build/vpw-082-action-smoke/workbench-report.json" in upload_step["with"]["path"]


def test_vpw082_docs_and_evidence_link_the_action_report_flow() -> None:
    examples_readme = EXAMPLES_README.read_text(encoding="utf-8")
    integration_doc = INTEGRATION_DOC.read_text(encoding="utf-8")
    readme = README_FILE.read_text(encoding="utf-8")
    evidence = VPW_082_EVIDENCE.read_text(encoding="utf-8")
    mkdocs = MKDOCS_FILE.read_text(encoding="utf-8")

    assert "workbench-report-artifacts.yml" in examples_readme
    assert "report workbench --input analysis.json --format markdown|json" in examples_readme
    assert "workbench-report-artifacts.yml" in integration_doc
    assert "provider-snapshot-file: provider-snapshot.json" in integration_doc
    assert 'locked-provider-data: "true"' in integration_doc
    assert "workbench-report-artifacts.yml" in readme
    assert "action-smoke" in evidence
    assert "no `secrets.*`" in evidence
    assert "evidence/vpw-082-github-action-reports.md" in mkdocs
