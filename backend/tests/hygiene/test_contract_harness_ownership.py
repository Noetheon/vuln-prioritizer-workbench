from __future__ import annotations

from utils.hygiene import ROOT


def test_import_contract_harness_owns_upload_and_parser_workflow_contracts() -> None:
    import_contract_root = ROOT / "tests/api/import_contracts"
    expected_contract_files = {
        "test_import_api_contracts.py",
        "test_import_execution_contracts.py",
        "test_import_parser_contracts.py",
        "test_import_security_contracts.py",
        "test_import_sidecar_contracts.py",
        "test_import_upload_boundary_contracts.py",
        "test_import_workflow_contracts.py",
        "test_decision_evidence_contract.py",
    }

    assert not (ROOT / "tests/api/test_workbench_import_upload_api.py").exists()
    assert not (ROOT / "tests/api/test_workbench_parser_fixture_matrix.py").exists()
    assert expected_contract_files.issubset(
        {path.name for path in import_contract_root.glob("test_*.py")}
    )
    assert (ROOT / "tests/utils/import_contract_fixtures.py").exists()
    assert (ROOT / "tests/utils/import_contracts.py").exists()
    assert (ROOT / "app/contracts/decision_evidence.py").exists()
    assert not (ROOT / "app/contracts/run_workflow.py").exists()


def test_report_and_workflow_contract_harness_own_artifact_and_matrix_contracts() -> None:
    report_contract_root = ROOT / "tests/api/report_contracts"
    workflow_contract_root = ROOT / "tests/api/workflow_contracts"

    assert not (ROOT / "tests/api/test_workbench_reports_api.py").exists()
    assert {
        "test_evidence_bundle_contracts.py",
        "test_report_api_contracts.py",
        "test_report_format_contracts.py",
        "test_report_snapshot_contracts.py",
    }.issubset({path.name for path in report_contract_root.glob("test_*.py")})
    assert (workflow_contract_root / "test_workbench_workflow_matrix.py").exists()
    assert (ROOT / "tests/utils/report_contract_fixtures.py").exists()
    assert (ROOT / "tests/utils/workbench_contracts.py").exists()
    assert (ROOT / "tests/utils/workbench_workflow_contracts.py").exists()
