from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from vuln_prioritizer.api.app import create_app, get_engine
from vuln_prioritizer.db import Finding, Vulnerability, WorkbenchRepository, create_session_factory
from vuln_prioritizer.workbench_config import WorkbenchSettings

ROOT = Path(__file__).resolve().parents[2]
DEMO_PROVIDER_SNAPSHOT = ROOT / "data" / "demo_provider_snapshot.json"
SAMPLE_CVES = ROOT / "data" / "sample_cves.txt"
TRIVY_REPORT = ROOT / "data" / "input_fixtures" / "trivy_report.json"
GRYPE_REPORT = ROOT / "data" / "input_fixtures" / "grype_report.json"
ASSET_CONTEXT = ROOT / "data" / "input_fixtures" / "example_asset_context.csv"
OPENVEX = ROOT / "data" / "input_fixtures" / "openvex_statements.json"
ATTACK_MAPPING = ROOT / "data" / "attack" / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"
ATTACK_METADATA = ROOT / "data" / "attack" / "attack_techniques_enterprise_16.1_subset.json"
EXPECTED_SAMPLE_CVES = {
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2023-44487",
    "CVE-2024-3094",
}


def _client(tmp_path: Path) -> TestClient:
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        provider_snapshot_dir=ROOT / "data",
        attack_artifact_dir=ROOT / "data" / "attack",
    )
    return TestClient(create_app(settings=settings))


def _client_and_settings(tmp_path: Path) -> tuple[TestClient, WorkbenchSettings]:
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        provider_snapshot_dir=ROOT / "data",
        attack_artifact_dir=ROOT / "data" / "attack",
    )
    return TestClient(create_app(settings=settings)), settings


def _create_project(client: TestClient) -> dict[str, Any]:
    response = client.post("/api/projects", json={"name": "online-shop-demo"})
    assert response.status_code == 200
    return response.json()


def _import_sample(client: TestClient, project_id: str) -> dict[str, Any]:
    response = client.post(
        f"/api/projects/{project_id}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", SAMPLE_CVES.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _import_payload(
    client: TestClient,
    project_id: str,
    *,
    input_format: str,
    filename: str,
    content: bytes,
    content_type: str,
) -> dict[str, Any]:
    response = client.post(
        f"/api/projects/{project_id}/imports",
        data={
            "input_format": input_format,
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={"file": (filename, content, content_type)},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_workbench_health_and_project_crud(tmp_path: Path) -> None:
    client = _client(tmp_path)

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["x-frame-options"] == "DENY"
    assert "object-src 'none'" in health.headers["content-security-policy"]

    bad_host = client.get("/api/health", headers={"host": "evil.example"})
    assert bad_host.status_code == 400

    version = client.get("/api/version")
    assert version.status_code == 200
    assert version.json()["app"] == "Vuln Prioritizer Workbench"

    project = _create_project(client)
    assert project["name"] == "online-shop-demo"

    projects = client.get("/api/projects")
    assert projects.status_code == 200
    assert projects.json()["items"][0]["id"] == project["id"]

    duplicate = client.post("/api/projects", json={"name": "online-shop-demo"})
    assert duplicate.status_code == 409
    duplicate_payload = duplicate.json()
    assert duplicate_payload["detail"] == "Project already exists."
    assert duplicate_payload["error"]["code"] == "conflict"


def test_workbench_import_findings_reports_and_evidence(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    run = _import_sample(client, project["id"])

    assert run["status"] == "completed"
    assert run["input_type"] == "cve-list"
    assert run["input_filename"] == "sample.txt"
    assert run["finished_at"] is not None
    assert run["summary"]["findings_count"] == len(EXPECTED_SAMPLE_CVES)
    assert run["summary"]["kev_hits"] >= 1
    assert run["summary"]["counts_by_priority"]
    assert run["provider_snapshot_id"]
    assert run["summary"]["provider_snapshot_id"] == run["provider_snapshot_id"]

    provider_status = client.get("/api/providers/status")
    assert provider_status.status_code == 200
    status_payload = provider_status.json()
    assert status_payload["status"] == "ok"
    assert status_payload["snapshot"]["content_hash"]
    assert status_payload["snapshot"]["selected_sources"] == ["nvd", "epss", "kev"]
    assert {source["name"] for source in status_payload["sources"]} == {"nvd", "epss", "kev"}

    project_runs = client.get(f"/api/projects/{project['id']}/runs")
    assert project_runs.status_code == 200
    assert [item["id"] for item in project_runs.json()["items"]] == [run["id"]]

    run_alias = client.get(f"/api/runs/{run['id']}")
    assert run_alias.status_code == 200
    assert run_alias.json()["id"] == run["id"]

    run_summary = client.get(f"/api/runs/{run['id']}/summary")
    assert run_summary.status_code == 200
    assert run_summary.json()["findings_count"] == len(EXPECTED_SAMPLE_CVES)

    findings = client.get(f"/api/projects/{project['id']}/findings")
    assert findings.status_code == 200
    items = findings.json()["items"]
    assert {item["cve_id"] for item in items} == EXPECTED_SAMPLE_CVES
    assert {item["status"] for item in items} == {"open"}
    assert [item["operational_rank"] for item in items] == sorted(
        item["operational_rank"] for item in items
    )

    filtered = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"q": "CVE-2024-3094"},
    )
    assert filtered.status_code == 200
    assert [item["cve_id"] for item in filtered.json()["items"]] == ["CVE-2024-3094"]
    assert filtered.json()["total"] == 1
    assert filtered.json()["limit"] == 100
    assert filtered.json()["offset"] == 0

    paged = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"limit": 2, "offset": 1, "sort": "cve"},
    )
    assert paged.status_code == 200
    paged_payload = paged.json()
    assert paged_payload["total"] == len(EXPECTED_SAMPLE_CVES)
    assert paged_payload["limit"] == 2
    assert [item["cve_id"] for item in paged_payload["items"]] == sorted(EXPECTED_SAMPLE_CVES)[1:3]

    kev_findings = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"kev": "true", "sort": "epss"},
    )
    assert kev_findings.status_code == 200
    assert kev_findings.json()["total"] >= 1
    assert all(item["in_kev"] for item in kev_findings.json()["items"])

    bad_sort = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"sort": "unsupported"},
    )
    assert bad_sort.status_code == 422
    assert bad_sort.json()["error"]["code"] == "validation_error"

    log4shell = next(item for item in items if item["cve_id"] == "CVE-2021-44228")
    detail = client.get(f"/api/findings/{log4shell['id']}")
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["finding"]["cve_id"] == "CVE-2021-44228"
    assert detail_payload["finding"]["provider_evidence"]["nvd"]["cve_id"] == "CVE-2021-44228"
    assert detail_payload["occurrences"][0]["source_format"] == "cve-list"
    assert detail_payload["occurrences"][0]["source_record_id"] == "line:1"

    explanation = client.get(f"/api/findings/{log4shell['id']}/explain")
    assert explanation.status_code == 200
    assert explanation.json()["cve_id"] == "CVE-2021-44228"
    assert explanation.json()["explanation"]["cve_id"] == "CVE-2021-44228"

    report_expectations = {
        "json": ("analysis-json", b'"locked_provider_data": true'),
        "markdown": ("markdown-summary", b"# Vulnerability Prioritization Summary"),
        "html": ("html-report", b"Vulnerability"),
        "csv": ("findings-csv", b"cve_id,priority,status"),
    }
    for report_format, (expected_kind, expected_content) in report_expectations.items():
        report = client.post(
            f"/api/analysis-runs/{run['id']}/reports",
            json={"format": report_format},
        )
        assert report.status_code == 200
        report_payload = report.json()
        assert report_payload["format"] == report_format
        assert report_payload["kind"] == expected_kind
        assert len(report_payload["sha256"]) == 64

        report_download = client.get(report_payload["download_url"])
        assert report_download.status_code == 200
        assert report_download.headers["content-disposition"].startswith("attachment;")
        assert report_download.headers["cache-control"] == "no-store"
        assert hashlib.sha256(report_download.content).hexdigest() == report_payload["sha256"]
        assert expected_content in report_download.content
        assert b"CVE-2021-44228" in report_download.content

        if report_format == "json":
            analysis_payload = json.loads(report_download.text)
            assert analysis_payload["metadata"]["input_format"] == "cve-list"
            assert analysis_payload["metadata"]["locked_provider_data"] is True
            assert {
                finding["cve_id"] for finding in analysis_payload["findings"]
            } == EXPECTED_SAMPLE_CVES

    bundle = client.post(f"/api/analysis-runs/{run['id']}/evidence-bundle")
    assert bundle.status_code == 200
    bundle_payload = bundle.json()
    assert len(bundle_payload["sha256"]) == 64
    bundle_download = client.get(bundle_payload["download_url"])
    assert bundle_download.status_code == 200
    assert hashlib.sha256(bundle_download.content).hexdigest() == bundle_payload["sha256"]
    assert bundle_download.content.startswith(b"PK")

    with zipfile.ZipFile(io.BytesIO(bundle_download.content)) as archive:
        names = set(archive.namelist())
        assert {"analysis.json", "report.html", "summary.md", "manifest.json"} <= names
        assert "input/sample.txt" in names

        analysis_payload = json.loads(archive.read("analysis.json"))
        assert analysis_payload["metadata"]["input_format"] == "cve-list"
        assert {
            finding["cve_id"] for finding in analysis_payload["findings"]
        } == EXPECTED_SAMPLE_CVES

        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["bundle_kind"] == "evidence-bundle"
        assert manifest["findings_count"] == len(EXPECTED_SAMPLE_CVES)
        assert manifest["included_input_copy"] is True
        assert manifest["source_analysis_sha256"]
        assert manifest["source_input_hashes"][0]["path"].endswith("sample.txt")
        assert (
            manifest["provider_snapshot"]["sha256"]
            == analysis_payload["metadata"]["provider_snapshot_hash"]
        )
        manifest_files = {item["path"]: item for item in manifest["files"]}
        for artifact_name in ["analysis.json", "report.html", "summary.md", "input/sample.txt"]:
            assert artifact_name in manifest_files
            assert (
                manifest_files[artifact_name]["sha256"]
                == hashlib.sha256(archive.read(artifact_name)).hexdigest()
            )
            assert (
                manifest["artifact_hashes"][artifact_name]
                == manifest_files[artifact_name]["sha256"]
            )

    assert bundle_payload["verify_url"] == f"/api/evidence-bundles/{bundle_payload['id']}/verify"
    verification = client.get(bundle_payload["verify_url"])
    assert verification.status_code == 200
    assert verification.json()["summary"]["ok"] is True


def test_workbench_imports_all_mvp_formats(tmp_path: Path) -> None:
    client = _client(tmp_path)
    cases = [
        (
            "generic-occurrence-csv",
            "generic.csv",
            (
                b"cve,component,version,purl,fix_version,target_kind,target_ref,"
                b"asset_id,criticality,exposure,environment,owner,business_service\n"
                b"CVE-2024-3094,xz,5.6.0-r0,pkg:apk/alpine/xz@5.6.0-r0,5.6.1-r2,"
                b"image,ghcr.io/acme/demo-app:1.0.0,api-gateway,critical,"
                b"internet-facing,prod,platform-team,customer-login\n"
            ),
            "text/csv",
            {"CVE-2024-3094"},
        ),
        (
            "trivy-json",
            "trivy.json",
            TRIVY_REPORT.read_bytes(),
            "application/json",
            {"CVE-2023-34362", "CVE-2024-3094", "CVE-2024-4577"},
        ),
        (
            "grype-json",
            "grype.json",
            GRYPE_REPORT.read_bytes(),
            "application/json",
            {"CVE-2023-34362", "CVE-2024-3094"},
        ),
    ]

    for index, (input_format, filename, content, content_type, expected_cves) in enumerate(cases):
        project = client.post("/api/projects", json={"name": f"format-{index}"}).json()
        run = _import_payload(
            client,
            project["id"],
            input_format=input_format,
            filename=filename,
            content=content,
            content_type=content_type,
        )
        assert run["status"] == "completed"
        assert run["input_type"] == input_format

        findings = client.get(f"/api/projects/{project['id']}/findings")
        assert findings.status_code == 200
        assert {item["cve_id"] for item in findings.json()["items"]} == expected_cves


def test_workbench_attack_import_exposes_ttp_context_and_navigator(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)

    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "trivy-json",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
            "attack_source": "ctid-json",
            "attack_mapping_file": ATTACK_MAPPING.name,
            "attack_technique_metadata_file": ATTACK_METADATA.name,
        },
        files={"file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")},
    )
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["summary"]["attack_enabled"] is True
    assert run["summary"]["attack_source"] == "ctid-mappings-explorer"
    assert run["summary"]["attack_mapped_cves"] >= 1
    assert (
        run["summary"]["attack_mapping_file_sha256"]
        == hashlib.sha256(ATTACK_MAPPING.read_bytes()).hexdigest()
    )
    assert (
        run["summary"]["attack_technique_metadata_file_sha256"]
        == hashlib.sha256(ATTACK_METADATA.read_bytes()).hexdigest()
    )
    assert run["summary"]["attack_metadata_format"] == "vuln-prioritizer-technique-json"

    findings = client.get(f"/api/projects/{project['id']}/findings", params={"sort": "cve"})
    assert findings.status_code == 200
    mapped = [item for item in findings.json()["items"] if item["attack_mapped"]]
    assert mapped
    assert all(item["threat_context_rank"] is not None for item in mapped)

    moveit = next(item for item in mapped if item["cve_id"] == "CVE-2023-34362")
    ttps = client.get(f"/api/findings/{moveit['id']}/ttps")
    assert ttps.status_code == 200
    ttp_payload = ttps.json()
    assert ttp_payload["source"] == "ctid"
    assert ttp_payload["review_status"] == "source_reviewed"
    assert ttp_payload["mapped"] is True
    assert ttp_payload["source_hash"] == hashlib.sha256(ATTACK_MAPPING.read_bytes()).hexdigest()
    assert ttp_payload["metadata_hash"] == hashlib.sha256(ATTACK_METADATA.read_bytes()).hexdigest()
    assert ttp_payload["source_path"].endswith(ATTACK_MAPPING.name)
    assert ttp_payload["metadata_path"].endswith(ATTACK_METADATA.name)
    assert {technique["attack_object_id"] for technique in ttp_payload["techniques"]} >= {"T1190"}

    top_techniques = client.get(f"/api/projects/{project['id']}/attack/top-techniques")
    assert top_techniques.status_code == 200
    assert any(item["technique_id"] == "T1190" for item in top_techniques.json()["items"])

    navigator = client.get(f"/api/analysis-runs/{run['id']}/attack/navigator-layer")
    assert navigator.status_code == 200
    assert any(item["techniqueID"] == "T1190" for item in navigator.json()["techniques"])

    bundle = client.post(f"/api/analysis-runs/{run['id']}/evidence-bundle")
    assert bundle.status_code == 200
    bundle_download = client.get(bundle.json()["download_url"])
    with zipfile.ZipFile(io.BytesIO(bundle_download.content)) as archive:
        names = set(archive.namelist())
        assert "attack-navigator-layer.json" in names
        manifest = json.loads(archive.read("manifest.json"))
        manifest_files = {item["path"]: item for item in manifest["files"]}
        analysis_payload = json.loads(archive.read("analysis.json"))
        assert (
            analysis_payload["metadata"]["attack_mapping_file_sha256"]
            == hashlib.sha256(ATTACK_MAPPING.read_bytes()).hexdigest()
        )
        assert analysis_payload["metadata"]["attack_technique_metadata_file_sha256"]
        assert "attack-navigator-layer.json" in manifest_files
        assert (
            manifest_files["attack-navigator-layer.json"]["sha256"]
            == hashlib.sha256(archive.read("attack-navigator-layer.json")).hexdigest()
        )


def test_workbench_import_accepts_context_vex_and_waiver_uploads(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    waiver = "\n".join(
        [
            "waivers:",
            "  - id: review-due-xz",
            "    cve_id: CVE-2024-3094",
            "    owner: risk-review",
            "    reason: Temporary acceptance for coordinated rollout.",
            "    expires_on: 2099-12-31",
            "    review_on: 2000-01-01",
            "    services: [customer-login]",
        ]
    ).encode()

    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "trivy-json",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={
            "file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json"),
            "asset_context_file": ("asset-context.csv", ASSET_CONTEXT.read_bytes(), "text/csv"),
            "vex_file": ("openvex.json", OPENVEX.read_bytes(), "application/json"),
            "waiver_file": ("waivers.yml", waiver, "text/yaml"),
        },
    )
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["summary"]["findings_count"] == 3

    findings = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"sort": "cve"},
    )
    assert findings.status_code == 200
    by_cve = {item["cve_id"]: item for item in findings.json()["items"]}
    assert by_cve["CVE-2023-34362"]["suppressed_by_vex"] is True
    assert by_cve["CVE-2023-34362"]["status"] == "suppressed"
    assert by_cve["CVE-2023-34362"]["vex_statuses"] == {"not_affected": 1}
    assert by_cve["CVE-2024-4577"]["under_investigation"] is True
    assert by_cve["CVE-2024-3094"]["waived"] is True
    assert by_cve["CVE-2024-3094"]["waiver_status"] == "review_due"
    assert by_cve["CVE-2024-3094"]["waiver_owner"] == "risk-review"
    assert by_cve["CVE-2024-3094"]["owner"] == "platform-team"
    assert by_cve["CVE-2024-3094"]["service"] == "customer-login"

    governance = client.get(f"/api/projects/{project['id']}/governance/rollups")
    assert governance.status_code == 200
    payload = governance.json()
    assert payload["total_findings"] == 3
    assert payload["waiver_summary"]["review_due_count"] == 1
    assert payload["vex_summary"]["suppressed_findings"] == 1
    assert payload["vex_summary"]["under_investigation_findings"] == 1
    assert payload["vex_summary"]["status_counts"]["not_affected"] == 1
    owner_labels = {item["label"] for item in payload["owners"]}
    service_labels = {item["label"] for item in payload["services"]}
    assert "platform-team" in owner_labels
    assert "customer-login" in service_labels

    markdown = client.post(
        f"/api/analysis-runs/{run['id']}/reports",
        json={"format": "markdown"},
    )
    assert markdown.status_code == 200
    markdown_download = client.get(markdown.json()["download_url"])
    assert markdown_download.status_code == 200
    assert "## Governance" in markdown_download.text
    assert "Top owners: platform-team" in markdown_download.text


def test_workbench_csv_report_escapes_spreadsheet_formulas(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    content = (
        b"cve,component,version,target_ref,asset_id,owner,business_service\n"
        b'CVE-2024-3094,"=HYPERLINK(""https://example.invalid"")",5.6.0,'
        b"repo:demo,asset-1,+owner,@service\n"
    )
    run = _import_payload(
        client,
        project["id"],
        input_format="generic-occurrence-csv",
        filename="generic.csv",
        content=content,
        content_type="text/csv",
    )
    report = client.post(
        f"/api/analysis-runs/{run['id']}/reports",
        json={"format": "csv"},
    )
    assert report.status_code == 200
    csv_report = client.get(report.json()["download_url"])
    assert csv_report.status_code == 200
    assert "'=HYPERLINK" in csv_report.text
    assert ",+owner," not in csv_report.text
    assert ",'+owner," in csv_report.text
    assert ",'@service," in csv_report.text


def test_workbench_rejects_unsupported_and_oversized_uploads(tmp_path: Path) -> None:
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        max_upload_mb=1,
    )
    client = TestClient(create_app(settings=settings))
    project = _create_project(client)

    bad_format = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "nessus-xml"},
        files={"file": ("scan.xml", b"<xml />", "application/xml")},
    )
    assert bad_format.status_code == 422

    path_traversal = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "trivy-json"},
        files={"file": ("../../trivy.json", b"{}", "application/json")},
    )
    assert path_traversal.status_code == 422
    assert "Upload filename is not allowed" in path_traversal.text
    assert not (tmp_path / "trivy.json").exists()

    context_path_traversal = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "cve-list"},
        files={
            "file": ("sample.txt", b"CVE-2024-3094\n", "text/plain"),
            "asset_context_file": ("../asset.csv", ASSET_CONTEXT.read_bytes(), "text/csv"),
        },
    )
    assert context_path_traversal.status_code == 422
    assert "Upload filename is not allowed" in context_path_traversal.text
    assert not any(settings.upload_dir.rglob("*"))

    oversized = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "cve-list"},
        files={"file": ("large.txt", b"A" * (2 * 1024 * 1024), "text/plain")},
    )
    assert oversized.status_code == 413


def test_workbench_rejects_untrusted_provider_snapshot_path(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)

    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": str(tmp_path / "private-snapshot.json"),
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert "Provider snapshot path is not allowed" in response.text


def test_workbench_downloads_reject_tampered_artifact_paths(tmp_path: Path) -> None:
    client, settings = _client_and_settings(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    session_factory = create_session_factory(get_engine(client.app))
    with session_factory() as session:
        repo = WorkbenchRepository(session)
        project = repo.create_project(name="artifact-tamper")
        run = repo.create_analysis_run(project_id=project.id, input_type="cve-list")
        report = repo.add_report(
            project_id=project.id,
            analysis_run_id=run.id,
            kind="analysis-json",
            format="json",
            path=str(outside),
            sha256=hashlib.sha256(outside.read_bytes()).hexdigest(),
        )
        session.commit()
        report_id = report.id

    response = client.get(f"/api/reports/{report_id}/download")
    assert response.status_code == 404

    valid_path = settings.report_dir / "run" / "analysis.json"
    valid_path.parent.mkdir(parents=True)
    valid_path.write_text("{}", encoding="utf-8")
    original_sha = hashlib.sha256(valid_path.read_bytes()).hexdigest()
    valid_path.write_text('{"tampered": true}', encoding="utf-8")

    with session_factory() as session:
        repo = WorkbenchRepository(session)
        project = repo.get_project_by_name("artifact-tamper")
        assert project is not None
        run = repo.list_analysis_runs(project.id)[0]
        checksum_report = repo.add_report(
            project_id=project.id,
            analysis_run_id=run.id,
            kind="analysis-json",
            format="json",
            path=str(valid_path),
            sha256=original_sha,
        )
        session.commit()
        checksum_report_id = checksum_report.id

    response = client.get(f"/api/reports/{checksum_report_id}/download")
    assert response.status_code == 409


def test_workbench_findings_api_handles_10k_pagination_smoke(tmp_path: Path) -> None:
    client = _client(tmp_path)
    session_factory = create_session_factory(get_engine(client.app))
    with session_factory() as session:
        repo = WorkbenchRepository(session)
        project = repo.create_project(name="ten-k-smoke")
        vulnerabilities = [
            Vulnerability(id=f"vuln-{index}", cve_id=f"CVE-2099-{index:05d}")
            for index in range(10_000)
        ]
        session.add_all(vulnerabilities)
        session.flush()
        session.add_all(
            [
                Finding(
                    id=f"finding-{index}",
                    project_id=project.id,
                    vulnerability_id=f"vuln-{index}",
                    cve_id=f"CVE-2099-{index:05d}",
                    status="open",
                    priority="Low",
                    priority_rank=4,
                    operational_rank=index + 1,
                    finding_json={},
                    explanation_json={},
                )
                for index in range(10_000)
            ]
        )
        session.commit()
        project_id = project.id

    response = client.get(
        f"/api/projects/{project_id}/findings",
        params={"sort": "cve", "limit": 100, "offset": 9900},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 10_000
    assert payload["limit"] == 100
    assert len(payload["items"]) == 100
    assert payload["items"][0]["cve_id"] == "CVE-2099-09900"
