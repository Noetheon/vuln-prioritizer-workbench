from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.import_contracts import completed_run_payload
from utils.sbom_fixtures import configure_scanner, sbom_content, vulnerability_match
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.models import Finding, WorkflowRun


@pytest.mark.parametrize("outcome", ["vulnerable", "zero", "unassigned"])
def test_sbom_scan_publishes_immutable_evidence_and_truthful_outcomes(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    outcome: str,
) -> None:
    env = workbench_api_env
    matches = [] if outcome == "zero" else [vulnerability_match(with_cve=outcome == "vulnerable")]
    root = configure_scanner(env, tmp_path, matches)
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)
    response = env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "cyclonedx-json",
            "sbom_scanner": "grype",
            "sbom_target_ref": "orders-service@1",
            "sbom_db_update": "false",
        },
        files={"file": ("inventory.json", sbom_content(), "application/json")},
    )
    run = completed_run_payload(env, response, headers=headers)
    assert run["status"] == "succeeded", json.dumps(run, indent=2)
    evidence = run["evidence"]
    assessment = evidence["sbom_assessment"]
    assert assessment["status"] == ("partial" if outcome == "unassigned" else "complete")
    assert assessment["target_ref"] == "orders-service@1"
    assert assessment["scanner_match_count"] == len(matches)
    assert assessment["unassigned_match_count"] == int(outcome == "unassigned")
    assert evidence["counts"]["finding_count"] == int(outcome == "vulnerable")
    assert assessment["input_sha256"] == hashlib.sha256(sbom_content()).hexdigest()
    refs = assessment["artifact_refs"]
    assert (root / refs["input"]).read_bytes() == sbom_content()
    assert (
        hashlib.sha256((root / refs["report"]).read_bytes()).hexdigest()
        == assessment["output_sha256"]
    )
    assert json.loads((root / refs["manifest"]).read_bytes()) == assessment
    with Session(env.engine) as session:
        workflow = session.exec(select(WorkflowRun)).one()
        assert len(workflow.result_ref_json["artifact_refs"]) == 3
        findings = session.exec(select(Finding)).all()
        assert len(findings) == int(outcome == "vulnerable")


def test_scanner_failure_does_not_publish_clean_evidence(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = workbench_api_env
    configure_scanner(env, tmp_path, [])
    (tmp_path / "grype").write_text(f"#!{Path(sys.executable).resolve()}\nraise SystemExit(2)\n")
    headers = local_api_headers(env.client)
    project = create_project_via_api(env.client, headers)
    response = env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "cyclonedx-json",
            "sbom_scanner": "grype",
            "sbom_target_ref": "orders-service@1",
        },
        files={"file": ("inventory.json", sbom_content(), "application/json")},
    )
    run = completed_run_payload(env, response, headers=headers)
    assert run["status"] == "failed"
    assert run["evidence"] is None
