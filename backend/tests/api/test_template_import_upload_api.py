from __future__ import annotations

import hashlib
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.template_workbench import (
    TemplateApiEnv,
    auth_headers,
    create_project_via_api,
)

from app import models as app_models
from app.services import TemplateAnalysisError

PROJECT_ROOT = Path(__file__).resolve().parents[3]
TRIVY_REPORT = PROJECT_ROOT / "data" / "input_fixtures" / "trivy_report.json"
ATTACK_MAPPING = PROJECT_ROOT / "data" / "attack" / "local_curated_low_confidence_vpw058.yml"


def test_valid_cve_list_upload_creates_analysis_run_and_stores_sha256(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"CVE-2024-3094\nCVE-2021-44228\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("Team Scan (prod).txt", content, "text/plain")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == project["id"]
    assert payload["input_type"] == "cve-list"
    assert payload["filename"] == "Team_Scan__prod_.txt"
    assert payload["status"] == "succeeded"
    assert payload["summary_json"]["input_sha256"] == expected_sha256
    assert payload["summary_json"]["occurrence_count"] == 2
    assert payload["summary_json"]["finding_count"] == 2
    assert payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert payload["summary_json"]["dedup_summary"]["reused_findings"] == 0
    assert payload["provider_snapshot_id"]
    assert payload["summary_json"]["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert payload["summary_json"]["analysis_service"]["pipeline"] == (
        "parse-persist-enrich-score-explain"
    )
    assert payload["summary_json"]["counts_by_priority"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert payload["summary_json"]["kev_hits"] >= 1
    assert payload["summary_json"]["created_findings"] == 2
    assert payload["summary_json"]["updated_findings"] == 0
    assert payload["summary_json"]["ignored_lines"] == 0
    assert payload["summary_json"]["input_upload"]["sha256"] == expected_sha256
    assert payload["summary_json"]["input_upload"]["original_filename"] == "Team Scan (prod).txt"
    assert payload["summary_json"]["input_upload"]["stored_filename"] == "Team_Scan__prod_.txt"
    assert payload["summary_json"]["input_upload"]["path"].startswith(str(upload_dir))
    assert Path(payload["summary_json"]["input_upload"]["path"]).read_bytes() == content
    assert payload["summary_json"]["import_job"]["status"] == "succeeded"
    assert [item["status"] for item in payload["summary_json"]["import_job"]["status_history"]] == [
        "pending",
        "running",
        "succeeded",
    ]
    assert payload["summary_json"]["parse_errors"] == []

    runs = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs/",
        headers=headers,
    )
    assert runs.status_code == 200
    assert runs.json()["count"] == 1
    assert runs.json()["data"][0]["id"] == payload["id"]
    assert runs.json()["data"][0]["status"] == "succeeded"

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    finding_payloads = findings.json()["data"]
    assert findings.json()["count"] == 2
    assert {item["priority"] for item in finding_payloads} == {"critical"}
    assert all(item["risk_score"] is not None for item in finding_payloads)
    assert all(item["operational_rank"] > 0 for item in finding_payloads)
    assert all(item["explanation_json"]["explanation"]["reasons"] for item in finding_payloads)
    assert all(
        item["explanation_json"]["decision_guidance"]["decision_statement"]
        for item in finding_payloads
    )

    summary = template_api_env.client.get(
        f"/api/v1/runs/{payload['id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["id"] == payload["id"]
    assert summary_payload["project_id"] == project["id"]
    assert summary_payload["status"] == "succeeded"
    assert summary_payload["created_findings"] == 2
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["ignored_lines"] == 0
    assert summary_payload["occurrence_count"] == 2
    assert summary_payload["finding_count"] == 2
    assert summary_payload["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert summary_payload["counts_by_priority"] == payload["summary_json"]["counts_by_priority"]
    assert summary_payload["kev_hits"] == payload["summary_json"]["kev_hits"]
    assert summary_payload["parse_errors"] == []
    assert summary_payload["input_upload"]["sha256"] == expected_sha256


def test_attack_import_exposes_template_finding_ttp_context(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "trivy-json",
            "attack_source": "local-curated",
            "attack_mapping_file": ATTACK_MAPPING.name,
        },
        files={"file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")},
    )

    assert response.status_code == 200, response.text
    run_payload = response.json()
    assert run_payload["summary_json"]["attack_mapped_cves"] == 1
    assert run_payload["summary_json"]["attack_source"] == "local-curated"

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"sort": "cve"},
    )
    assert findings.status_code == 200
    finding_items = findings.json()["data"]
    mapped = next(item for item in finding_items if item["cve_id"] == "CVE-2023-34362")
    unmapped = next(item for item in finding_items if item["cve_id"] == "CVE-2024-3094")

    mapped_detail = template_api_env.client.get(
        f"/api/v1/findings/{mapped['id']}",
        headers=headers,
    )
    assert mapped_detail.status_code == 200
    attack_context = mapped_detail.json()["attack_context"]
    assert attack_context["mapped"] is True
    assert attack_context["source"] == "local-curated"
    assert attack_context["confidence"] == "low"
    assert attack_context["low_confidence"] is True
    assert attack_context["review_status"] == "needs_review"
    assert attack_context["mappings"][0]["technique_id"] == "T1190"
    assert "reviewed" in attack_context["mappings"][0]["rationale"].lower()
    assert "payload" not in attack_context["mappings"][0]["rationale"].lower()
    assert attack_context["techniques"][0]["technique_id"] == "T1190"
    assert "initial-access" in attack_context["tactics"]
    assert "defensive triage" in attack_context["defensive_note"]

    unmapped_detail = template_api_env.client.get(
        f"/api/v1/findings/{unmapped['id']}",
        headers=headers,
    )
    assert unmapped_detail.status_code == 200
    empty_context = unmapped_detail.json()["attack_context"]
    assert empty_context["mapped"] is False
    assert empty_context["mappings"] == []
    assert empty_context["techniques"] == []


def test_decision_api_endpoints_expose_explain_summary_and_cvss_comparison(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"CVE-2021-44228\nCVE-2024-3094\n"

    import_response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("decision-api.txt", content, "text/plain")},
    )
    assert import_response.status_code == 200
    run_payload = import_response.json()
    assert Path(run_payload["summary_json"]["input_upload"]["path"]).is_relative_to(upload_dir)

    findings_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings_response.status_code == 200
    findings_payload = findings_response.json()
    assert findings_payload["count"] == 2
    finding_id = findings_payload["data"][0]["id"]

    explain_response = template_api_env.client.get(
        f"/api/v1/findings/{finding_id}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 200
    explain_payload = explain_response.json()
    assert explain_payload["finding_id"] == finding_id
    assert explain_payload["project_id"] == project["id"]
    assert explain_payload["priority"] == "critical"
    assert explain_payload["decision_explanation"]["reason_codes"]
    assert explain_payload["decision_guidance"]["decision_statement"]
    assert explain_payload["provider_evidence"]["nvd"]
    assert explain_payload["data_quality_confidence"] in {"high", "medium", "low"}

    project_summary_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/summary",
        headers=headers,
    )
    assert project_summary_response.status_code == 200
    project_summary = project_summary_response.json()
    assert project_summary["project_id"] == project["id"]
    assert project_summary["finding_count"] == 2
    assert project_summary["open_finding_count"] == 2
    assert project_summary["counts_by_priority"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert project_summary["counts_by_status"] == {
        "open": 2,
        "in_review": 0,
        "remediating": 0,
        "fixed": 0,
        "accepted": 0,
        "suppressed": 0,
    }
    assert project_summary["kev_hits"] >= 1
    assert project_summary["epss_hits"] == 2
    assert project_summary["cvss_known_count"] == 2
    assert project_summary["latest_run_id"] == run_payload["id"]
    assert project_summary["latest_run_status"] == "succeeded"

    comparison_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/compare/cvss-only",
        headers=headers,
    )
    assert comparison_response.status_code == 200
    comparison_payload = comparison_response.json()
    assert comparison_payload["project_id"] == project["id"]
    assert comparison_payload["methodology"]["baseline"] == "cvss-only"
    assert comparison_payload["summary"]["total"] == 2
    assert comparison_payload["counts"]["enriched"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert {item["cve_id"] for item in comparison_payload["comparisons"]} == {
        "CVE-2021-44228",
        "CVE-2024-3094",
    }


def test_double_import_deduplicates_findings_and_appends_occurrences(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    content = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity,owner,business_service,exposure",
            (
                "CVE-2024-3094,build-host-1,xz,5.6.0,"
                "pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,team-platform,payments,public"
            ),
            (
                "CVE-2024-4577,web-tier,php-cgi,8.3.7,"
                "pkg:deb/debian/php-cgi@8.3.7,HIGH,team-web,checkout,internal"
            ),
            "",
        ]
    ).encode()

    first = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )
    assert first.status_code == 200, first.text
    first_payload = first.json()
    assert first_payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert first_payload["summary_json"]["dedup_summary"]["reused_findings"] == 0
    assert {
        item["action"] for item in first_payload["summary_json"]["dedup_summary"]["decisions"]
    } == {"created"}

    first_findings, first_occurrence_count = _finding_state(template_api_env, project_id)
    first_decisions = _decision_state(first_findings)
    first_seen = {finding.cve_id: finding.first_seen_at for finding in first_findings}
    first_last_seen = {finding.cve_id: finding.last_seen_at for finding in first_findings}
    first_dedup_keys = {finding.cve_id: finding.dedup_key for finding in first_findings}

    second = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )
    assert second.status_code == 200, second.text
    second_payload = second.json()
    dedup_summary = second_payload["summary_json"]["dedup_summary"]
    assert second_payload["summary_json"]["occurrence_count"] == 2
    assert second_payload["summary_json"]["finding_count"] == 2
    assert second_payload["summary_json"]["created_findings"] == 0
    assert second_payload["summary_json"]["updated_findings"] == 2
    assert dedup_summary["created_findings"] == 0
    assert dedup_summary["updated_findings"] == 2
    assert dedup_summary["reused_findings"] == 2
    assert dedup_summary["decision_count"] == 2
    assert {item["action"] for item in dedup_summary["decisions"]} == {"reused"}
    assert all(item["dedup_key"].startswith("vpw019:") for item in dedup_summary["decisions"])
    assert all(
        item["asset_ref"] in {"build-host-1", "web-tier"} for item in dedup_summary["decisions"]
    )

    second_findings, second_occurrence_count = _finding_state(template_api_env, project_id)
    second_decisions = _decision_state(second_findings)
    assert len(first_findings) == 2
    assert first_occurrence_count == 2
    assert len(second_findings) == 2
    assert second_occurrence_count == 4
    assert second_decisions == first_decisions
    assert {finding.cve_id: finding.first_seen_at for finding in second_findings} == first_seen
    assert {finding.cve_id: finding.dedup_key for finding in second_findings} == first_dedup_keys
    assert all(
        finding.last_seen_at > first_last_seen[finding.cve_id] for finding in second_findings
    )
    findings_response = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"sort": "cve"},
    )
    assert findings_response.status_code == 200, findings_response.text
    findings_by_cve = {item["cve_id"]: item for item in findings_response.json()["data"]}
    assert findings_by_cve["CVE-2024-3094"]["component_name"] == "xz"
    assert findings_by_cve["CVE-2024-3094"]["component_version"] == "5.6.0"
    assert findings_by_cve["CVE-2024-3094"]["asset_key"] == "build-host-1"
    assert findings_by_cve["CVE-2024-3094"]["owner"] == "team-platform"
    assert findings_by_cve["CVE-2024-3094"]["business_service"] == "payments"
    assert findings_by_cve["CVE-2024-3094"]["exposure"] == "internet-facing"
    assert findings_by_cve["CVE-2024-4577"]["owner"] == "team-web"
    assert findings_by_cve["CVE-2024-4577"]["business_service"] == "checkout"
    assert findings_by_cve["CVE-2024-4577"]["exposure"] == "internal"

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 2

    summary = template_api_env.client.get(
        f"/api/v1/runs/{second_payload['id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["created_findings"] == 0
    assert summary_payload["updated_findings"] == 2
    assert summary_payload["occurrence_count"] == 2
    assert summary_payload["finding_count"] == 2
    assert summary_payload["dedup_summary"]["reused_findings"] == 2
    assert {item["action"] for item in summary_payload["dedup_summary"]["decisions"]} == {"reused"}
    assert (
        summary_payload["counts_by_priority"]
        == second_payload["summary_json"]["counts_by_priority"]
    )


def test_analysis_failure_persists_failed_run_without_partial_findings(
    monkeypatch: pytest.MonkeyPatch,
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    def _fail_analysis(*args: object, **kwargs: object) -> object:
        raise TemplateAnalysisError("scoring failed")

    monkeypatch.setattr(
        "app.api.routes.imports.AnalysisService.analyze_import",
        _fail_analysis,
    )

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("sample.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["message"] == "Import analysis failed."
    assert detail["analysis_error"]["stage"] == "enrich_score_explain"
    assert "scoring failed" in detail["analysis_error"]["message"]

    run = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["status"] == "failed"
    assert run_payload["summary_json"]["analysis_error"]["stage"] == "enrich_score_explain"
    assert run_payload["summary_json"]["created_findings"] == 0
    assert run_payload["summary_json"]["updated_findings"] == 0

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 0


def test_same_cve_on_different_assets_creates_distinct_findings(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    content = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            "CVE-2024-3094,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "CVE-2024-3094,build-host-2,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "",
        ]
    ).encode()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("same-cve-assets.csv", content, "text/csv")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["summary_json"]["finding_count"] == 2
    assert payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert {
        item["asset_ref"] for item in payload["summary_json"]["dedup_summary"]["decisions"]
    } == {"build-host-1", "build-host-2"}

    findings, occurrence_count = _finding_state(template_api_env, project_id)
    assert len(findings) == 2
    assert occurrence_count == 2
    assert len({finding.dedup_key for finding in findings}) == 2


@pytest.mark.parametrize(
    ("input_type", "filename", "content_type", "detail"),
    [
        ("unknown", "scan.txt", "text/plain", "Unsupported input type"),
        ("cve-list", "scan.json", "text/plain", "File extension does not match input type"),
        (
            "cve-list",
            "scan.txt",
            "application/json",
            "Upload content type does not match input type",
        ),
    ],
)
def test_upload_rejects_unknown_input_type_bad_extension_and_mime(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    input_type: str,
    filename: str,
    content_type: str,
    detail: str,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": input_type},
        files={"file": (filename, b"CVE-2024-3094\n", content_type)},
    )

    assert response.status_code == 422
    assert detail in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0


def test_upload_rejects_oversized_file_without_persisting_run_or_file(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path, max_upload_mb=1)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("large.txt", b"A" * (1024 * 1024 + 1), "text/plain")},
    )

    assert response.status_code == 413
    assert "Upload exceeds configured limit" in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


def test_upload_rejects_path_traversal_filename(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    outside = tmp_path / "evil.txt"

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("../../evil.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert "Upload filename is not allowed" in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
    assert not outside.exists()
    assert not upload_dir.exists()


def test_parse_errors_are_structured_and_failed_run_is_persisted(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"CVE-2024-3094\nnot-a-cve\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("bad.txt", content, "text/plain")},
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["message"] == "Import parsing failed."
    assert detail["analysis_run_id"]
    assert detail["ignored_lines"] == 0
    assert detail["parse_errors"][0]["input_type"] == "cve-list"
    assert detail["parse_errors"][0]["filename"] == "bad.txt"
    assert detail["parse_errors"][0]["line"] == 2
    assert detail["parse_errors"][0]["field"] == "cve_id"
    assert detail["parse_errors"][0]["value"] == "not-a-cve"
    assert "line 2" in detail["parse_errors"][0]["message"]
    assert "not-a-cve" in detail["parse_errors"][0]["message"]

    run = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    payload = run.json()
    assert payload["status"] == "failed"
    assert [item["status"] for item in payload["error_json"]["import_job"]["status_history"]] == [
        "pending",
        "running",
        "failed",
    ]
    assert payload["error_json"]["parse_errors"] == detail["parse_errors"]
    assert payload["summary_json"]["parse_errors"] == detail["parse_errors"]
    assert payload["summary_json"]["input_upload"]["sha256"] == expected_sha256
    assert Path(payload["summary_json"]["input_upload"]["path"]).is_relative_to(upload_dir)
    assert Path(payload["summary_json"]["input_upload"]["path"]).read_bytes() == content

    summary = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["status"] == "failed"
    assert summary_payload["created_findings"] == 0
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["ignored_lines"] == 0
    assert summary_payload["parse_errors"] == detail["parse_errors"]


def test_summary_tracks_ignored_cve_list_lines(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"# comment\n\nCVE-2024-3094\n"

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("with-ignored-lines.txt", content, "text/plain")},
    )

    assert response.status_code == 200, response.text
    run_id = response.json()["id"]
    summary = template_api_env.client.get(f"/api/v1/runs/{run_id}/summary", headers=headers)
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["ignored_lines"] == 2
    assert summary_payload["created_findings"] == 1
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["parse_errors"] == []


def _configure_upload_dir(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    *,
    max_upload_mb: int = 25,
) -> Path:
    upload_dir = tmp_path / "template-import-uploads"
    active_settings = template_api_env.client.app.state.template_settings
    template_api_env.client.app.state.template_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str(upload_dir),
        PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
        ATTACK_ARTIFACT_DIR=str(PROJECT_ROOT / "data" / "attack"),
        MAX_UPLOAD_MB=max_upload_mb,
    )
    return upload_dir.resolve(strict=False)


def _run_count(template_api_env: TemplateApiEnv, project_id: uuid.UUID) -> int:
    with Session(template_api_env.engine) as session:
        return len(
            template_api_env.repositories.RunRepository(session).list_analysis_runs(project_id)
        )


def _finding_state(
    template_api_env: TemplateApiEnv,
    project_id: uuid.UUID,
) -> tuple[list[app_models.Finding], int]:
    with Session(template_api_env.engine) as session:
        findings = list(
            session.exec(
                select(app_models.Finding)
                .where(app_models.Finding.project_id == project_id)
                .order_by(app_models.Finding.cve_id)
            )
        )
        occurrence_count = len(
            session.exec(
                select(app_models.FindingOccurrence)
                .join(app_models.Finding)
                .where(app_models.Finding.project_id == project_id)
            ).all()
        )
        return findings, occurrence_count


def _decision_state(findings: list[app_models.Finding]) -> dict[str, dict[str, object]]:
    values: dict[str, dict[str, object]] = {}
    for finding in findings:
        explanation = finding.explanation_json.get("explanation", {})
        guidance = finding.explanation_json.get("decision_guidance", {})
        values[finding.cve_id] = {
            "priority": str(finding.priority),
            "priority_rank": finding.priority_rank,
            "risk_score": finding.risk_score,
            "operational_rank": finding.operational_rank,
            "reason_codes": tuple(explanation.get("reason_codes", [])),
            "decision_template": guidance.get("template"),
        }
    return values
