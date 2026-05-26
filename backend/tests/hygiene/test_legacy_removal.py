from __future__ import annotations

from utils.hygiene import ROOT, SRC_ROOT, _imported_modules


def test_legacy_workbench_runtime_modules_are_removed() -> None:
    removed_paths = [
        SRC_ROOT / "api",
        SRC_ROOT / "web",
        SRC_ROOT / "db",
        SRC_ROOT / "provider_scheduler.py",
        SRC_ROOT / "workbench_config.py",
        SRC_ROOT / "commands" / "db.py",
        SRC_ROOT / "commands" / "web.py",
    ]

    assert [path for path in removed_paths if path.exists()] == []
    assert sorted(SRC_ROOT.glob("services/workbench_*.py")) == []


def test_legacy_cli_adapter_modules_are_removed() -> None:
    assert not (ROOT / "src/vuln_prioritizer/cli.py").exists()
    assert not (ROOT / "src/vuln_prioritizer/cli_options.py").exists()
    assert not (ROOT / "src/vuln_prioritizer/cli_support").exists()
    assert not (ROOT / "src/vuln_prioritizer/commands").exists()


def test_legacy_reporter_and_terminal_facades_are_removed() -> None:
    removed_modules = (
        "reporter.py",
        "reporting_state.py",
        "reporting_terminal.py",
        "reporting_terminal_tables.py",
        "reporting_terminal_summary.py",
        "reporting_terminal_explain.py",
        "runtime_config.py",
        "state_store.py",
        "models_state.py",
        "reporting_workbench.py",
        "reporting_io.py",
        "parser.py",
    )

    for module in removed_modules:
        assert not (ROOT / f"src/vuln_prioritizer/{module}").exists()


def test_legacy_cli_evidence_bundle_writer_modules_are_removed() -> None:
    removed_modules = (
        "reporting_evidence.py",
        "reporting_evidence_archive.py",
        "reporting_evidence_attack.py",
        "reporting_evidence_bundle.py",
        "reporting_evidence_governance.py",
        "reporting_evidence_inputs.py",
        "reporting_evidence_provider.py",
        "reporting_evidence_verify.py",
        "sarif_validation.py",
    )

    for module in removed_modules:
        assert not (ROOT / f"src/vuln_prioritizer/{module}").exists()

    imports = _imported_modules("app/services/report_bundle.py")
    assert "app.services.report_bundle_archive_verification" in imports


def test_legacy_domain_reporting_facades_are_removed() -> None:
    removed_modules = (
        "reporting_executive.py",
        "reporting_executive_constants.py",
        "reporting_executive_model.py",
        "reporting_executive_model_artifacts.py",
        "reporting_executive_model_attack.py",
        "reporting_executive_model_builder.py",
        "reporting_executive_model_evidence.py",
        "reporting_executive_model_findings.py",
        "reporting_executive_model_helpers.py",
        "reporting_executive_model_overview.py",
        "reporting_executive_model_provider.py",
        "reporting_executive_model_quality.py",
        "reporting_executive_model_remediation.py",
        "reporting_executive_renderer.py",
        "reporting_executive_sections.py",
        "reporting_executive_sections_attack_charts.py",
        "reporting_executive_sections_charts.py",
        "reporting_executive_sections_chrome.py",
        "reporting_executive_sections_components.py",
        "reporting_executive_sections_evidence.py",
        "reporting_executive_sections_remediation_charts.py",
        "reporting_executive_sections_risk_charts.py",
        "reporting_executive_sections_scatter.py",
        "reporting_executive_sections_summary.py",
        "reporting_executive_sections_top.py",
        "reporting_executive_utils.py",
        "reporting_format.py",
        "reporting_html.py",
        "reporting_markdown.py",
        "reporting_markdown_analysis.py",
        "reporting_payloads.py",
        "reporting_payloads_sarif.py",
        "reporting_payloads_summary.py",
    )

    for module in removed_modules:
        assert not (ROOT / f"src/vuln_prioritizer/{module}").exists()
