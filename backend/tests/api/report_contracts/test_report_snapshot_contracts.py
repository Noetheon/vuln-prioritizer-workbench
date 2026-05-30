from __future__ import annotations

import csv
import hashlib
import json
import zipfile
from datetime import UTC, datetime
from io import BytesIO, StringIO

import jsonschema
import pytest
from utils.report_contract_fixtures import (
    VPW054_DEMO_ARTIFACTS,
    VPW054_HTML_SNAPSHOT,
    VPW054_SECRET_MARKERS,
    _vpw050_snapshot_payload,
    _vpw051_snapshot_payload,
    _vpw054_demo_payload,
    _vpw060_snapshot_layer,
)
from utils.workbench_contracts import (
    _load_schema,
    _normalize_html_snapshot,
    _repo_root,
)
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
)

from app.services import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_findings_csv,
    render_html_executive_report,
    render_markdown_report,
)
from app.services.report_contracts import CSV_FINDINGS_COLUMNS


def test_vpw050_analysis_schema_rejects_contract_drift() -> None:
    schema = _load_schema("analysis-result.v2.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    valid = json.loads(
        (_repo_root() / "docs" / "evidence" / "vpw-050-analysis-result.v2.json").read_text(
            encoding="utf-8"
        )
    )

    jsonschema.validate(valid, schema)

    missing_required = dict(valid)
    missing_required.pop("findings")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(missing_required, schema)

    unexpected_top_level = dict(valid)
    unexpected_top_level["unexpected_top_level"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(unexpected_top_level, schema)

    malformed_finding = json.loads(json.dumps(valid))
    malformed_finding["findings"][0].pop("recommendation")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(malformed_finding, schema)


def test_vpw050_committed_evidence_artifacts_are_contract_valid() -> None:
    evidence_dir = _repo_root() / "docs" / "evidence"
    schema = _load_schema("analysis-result.v2.schema.json")
    analysis_json = json.loads(
        (evidence_dir / "vpw-050-analysis-result.v2.json").read_text(encoding="utf-8")
    )

    jsonschema.validate(analysis_json, schema)
    assert analysis_json["schema"] == "analysis-result.v2"
    assert analysis_json["analysis_run"]["id"] == "00000000-0000-4000-8000-000000000050"
    assert [finding["cve_id"] for finding in analysis_json["findings"]] == [
        DEMO_CVE_XZ,
        DEMO_CVE_LOG4SHELL,
    ]

    findings_csv = (evidence_dir / "vpw-050-findings.csv").read_text(encoding="utf-8")
    reader = csv.DictReader(StringIO(findings_csv))
    assert reader.fieldnames == CSV_FINDINGS_COLUMNS
    rows = list(reader)
    assert [row["cve_id"] for row in rows] == [DEMO_CVE_XZ, DEMO_CVE_LOG4SHELL]
    assert rows[0]["decision_sla"] == "Emergency / 24h"
    assert rows[1]["attack_techniques"] == "T1190"


def test_vpw052_committed_verification_evidence_is_contract_valid() -> None:
    schema = _load_schema("evidence-bundle-verification-report.schema.json")
    evidence_dir = _repo_root() / "docs" / "evidence"
    positive = json.loads(
        (evidence_dir / "vpw-052-positive-verification.json").read_text(encoding="utf-8")
    )
    tampered = json.loads(
        (evidence_dir / "vpw-052-tampered-verification.json").read_text(encoding="utf-8")
    )

    jsonschema.validate(positive, schema)
    assert positive["summary"]["ok"] is True
    assert positive["summary"]["verified_files"] == 4
    assert {item["status"] for item in positive["items"]} == {"ok"}

    jsonschema.validate(tampered, schema)
    assert tampered["summary"]["ok"] is False
    assert tampered["summary"]["modified_files"] == 1
    assert [item["path"] for item in tampered["items"] if item["status"] == "modified"] == [
        "analysis.json"
    ]


def test_vpw051_evidence_bundle_renderer_snapshot_is_stable() -> None:
    payload = _vpw051_snapshot_payload()
    bundle, manifest = render_evidence_bundle_zip(payload)

    with zipfile.ZipFile(BytesIO(bundle)) as archive:
        assert sorted(archive.namelist()) == [
            "analysis.json",
            "executive.html",
            "findings.csv",
            "manifest.json",
            "provider-snapshot.json",
            "results.sarif",
            "technical.md",
        ]
        stored_manifest = json.loads(archive.read("manifest.json"))
        assert manifest == stored_manifest
        assert (
            archive.read("analysis.json")
            == (_repo_root() / "docs" / "evidence" / "vpw-051-analysis.json").read_bytes()
        )
        assert (
            archive.read("manifest.json")
            == (_repo_root() / "docs" / "evidence" / "vpw-051-manifest.json").read_bytes()
        )
        for item in manifest["files"]:
            assert item["sha256"] == hashlib.sha256(archive.read(item["path"])).hexdigest()


def test_vpw060_attack_navigator_layer_snapshot_is_stable() -> None:
    layer = _vpw060_snapshot_layer()

    assert layer == json.loads(
        (_repo_root() / "docs" / "evidence" / "vpw-060-attack-navigator-layer.json").read_text(
            encoding="utf-8"
        )
    )


def test_vpw048_markdown_report_snapshot_is_stable() -> None:
    payload = MarkdownReportPayload(
        generated_at=datetime(2026, 4, 29, 12, 0, tzinfo=UTC),
        project_id="00000000-0000-4000-8000-000000000048",
        project_name="Snapshot Project <script>alert(1)</script>",
        run_id="00000000-0000-4000-8000-000000000049",
        run_status="completed",
        input_type="cve-list",
        filename="known-cves.txt",
        summary={"finding_count": 2},
        findings=[
            MarkdownReportFinding(
                operational_rank=1,
                cve_id=DEMO_CVE_XZ,
                priority="critical",
                status="open",
                risk_score=100.0,
                epss=0.846,
                cvss_base_score=10.0,
                in_kev=False,
                asset="Payments API",
                component="xz 5.6.0-r0",
                rationale="Internet-facing production asset with critical score.",
                recommended_action="Patch [open](javascript:alert(1)) now.",
                data_quality_confidence="high",
                data_quality_flags=[],
            ),
            MarkdownReportFinding(
                operational_rank=2,
                cve_id=DEMO_CVE_LOG4SHELL,
                priority="high",
                status="in_review",
                risk_score=94.2,
                epss=0.944,
                cvss_base_score=10.0,
                in_kev=True,
                asset="Ops API",
                component="log4j-core 2.14.1",
                rationale="CISA KEV listing and vulnerable component evidence.",
                recommended_action="Patch via vendor upgrade.",
                data_quality_confidence="medium",
                data_quality_flags=["missing_asset_owner - Owner is not set"],
            ),
        ],
        provider_snapshot=MarkdownProviderSnapshot(
            id="00000000-0000-4000-8000-000000000050",
            content_hash="sha256:vpw048-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            source_hashes={"provider_snapshot": "sha256:vpw048-snapshot"},
            source_metadata={
                "locked_provider_data": True,
                "selected_sources": ["nvd", "epss", "kev"],
                "source_path": "demo_provider_snapshot.json",
                "item_count": 2,
            },
        ),
    )
    snapshot_path = _repo_root() / "backend/tests/api/snapshots" / "vpw_048_technical_report.md"

    assert render_markdown_report(payload) == snapshot_path.read_text(encoding="utf-8")


def test_vpw049_html_report_snapshot_is_stable() -> None:
    payload = MarkdownReportPayload(
        generated_at=datetime(2026, 4, 29, 12, 0, tzinfo=UTC),
        project_id="00000000-0000-4000-8000-000000000049",
        project_name="Executive Snapshot <script>alert(1)</script>",
        run_id="00000000-0000-4000-8000-000000000155",
        run_status="completed",
        input_type="cve-list",
        filename="known-cves.html",
        summary={"finding_count": 2},
        findings=[
            MarkdownReportFinding(
                operational_rank=1,
                cve_id=DEMO_CVE_XZ,
                priority="critical",
                status="open",
                risk_score=100.0,
                epss=0.846,
                cvss_base_score=10.0,
                in_kev=False,
                asset="Payments API",
                component="xz 5.6.0-r0",
                rationale="Internet-facing production asset with critical score.",
                recommended_action="Patch [open](javascript:alert(1)) now.",
                data_quality_confidence="high",
                decision_statement=(
                    "Decision Statement: patch CVE-2024-3094 on Payments API "
                    "within the emergency SLA."
                ),
                business_impact=(
                    "Customer payment traffic depends on the affected production API; "
                    "delay increases outage and fraud exposure."
                ),
                decision_sla="Emergency / 24h",
                data_quality_flags=[],
            ),
            MarkdownReportFinding(
                operational_rank=2,
                cve_id=DEMO_CVE_LOG4SHELL,
                priority="high",
                status="in_review",
                risk_score=94.2,
                epss=0.944,
                cvss_base_score=10.0,
                in_kev=True,
                asset="Ops API",
                component="log4j-core 2.14.1",
                rationale="CISA KEV listing and vulnerable component evidence.",
                recommended_action="Patch via vendor upgrade.",
                data_quality_confidence="medium",
                decision_statement=(
                    "Decision Statement: patch CVE-2021-44228 after owner "
                    "validation and compensating control review."
                ),
                business_impact="Operational tooling exposure requires management visibility.",
                decision_sla="Emergency / 24h",
                data_quality_flags=["missing_asset_owner - Owner is not set"],
            ),
        ],
        provider_snapshot=MarkdownProviderSnapshot(
            id="00000000-0000-4000-8000-000000000051",
            content_hash="sha256:vpw049-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            source_hashes={"provider_snapshot": "sha256:vpw049-snapshot"},
            source_metadata={
                "locked_provider_data": True,
                "selected_sources": ["nvd", "epss", "kev"],
                "source_path": "demo_provider_snapshot.json",
                "item_count": 2,
            },
        ),
    )
    snapshot_path = _repo_root() / "backend/tests/api/snapshots" / "vpw_049_executive_report.html"

    assert render_html_executive_report(payload) == snapshot_path.read_text(encoding="utf-8")


def test_vpw050_analysis_json_export_snapshot_is_stable() -> None:
    payload = _vpw050_snapshot_payload()
    snapshot_path = _repo_root() / "backend/tests/api/snapshots" / "vpw_050_analysis_result.v2.json"

    assert render_analysis_result_json(payload) == snapshot_path.read_text(encoding="utf-8")


def test_vpw050_findings_csv_export_snapshot_is_stable() -> None:
    payload = _vpw050_snapshot_payload()
    snapshot_path = _repo_root() / "backend/tests/api/snapshots" / "vpw_050_findings.csv"

    assert render_findings_csv(payload) == snapshot_path.read_text(encoding="utf-8")


def test_vpw054_demo_report_artifacts_match_current_renderers() -> None:
    payload = _vpw054_demo_payload()
    repo_root = _repo_root()
    rendered = {
        "markdown": render_markdown_report(payload),
        "html": render_html_executive_report(payload),
        "json": render_analysis_result_json(payload),
    }

    for artifact_type, relative_path in VPW054_DEMO_ARTIFACTS.items():
        artifact_path = repo_root / relative_path
        assert artifact_path.read_text(encoding="utf-8") == rendered[artifact_type]

    jsonschema.validate(
        json.loads(rendered["json"]),
        _load_schema("analysis-result.v2.schema.json"),
    )


def test_vpw054_normalized_html_report_snapshot_is_stable() -> None:
    payload = _vpw054_demo_payload()
    snapshot_path = _repo_root() / VPW054_HTML_SNAPSHOT

    assert _normalize_html_snapshot(
        render_html_executive_report(payload)
    ) == snapshot_path.read_text(encoding="utf-8")


def test_vpw054_demo_report_artifacts_are_linked_and_secret_free() -> None:
    repo_root = _repo_root()
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    evidence = (repo_root / "docs" / "evidence" / "vpw-054-report-snapshots.md").read_text(
        encoding="utf-8"
    )
    combined_artifacts: list[str] = []

    for relative_path in VPW054_DEMO_ARTIFACTS.values():
        artifact_link = relative_path.as_posix()
        assert artifact_link in readme
        assert artifact_link in evidence
        combined_artifacts.append((repo_root / relative_path).read_text(encoding="utf-8"))

    combined_text = "\n".join(combined_artifacts).lower()
    for marker in VPW054_SECRET_MARKERS:
        assert marker not in combined_text
