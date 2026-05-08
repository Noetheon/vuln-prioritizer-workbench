from __future__ import annotations

from datetime import UTC, datetime

from app.services.report_models import MarkdownReportFinding, MarkdownReportPayload
from app.services.report_sarif import render_sarif_report


def _payload_with_findings(findings: list[MarkdownReportFinding]) -> MarkdownReportPayload:
    return MarkdownReportPayload(
        generated_at=datetime(2026, 5, 1, tzinfo=UTC),
        project_id="project-1",
        project_name="Payments",
        run_id="run-1",
        run_status="completed",
        input_type="generic-occurrence-csv",
        filename="findings.csv",
        summary={},
        provider_snapshot=None,
        findings=findings,
    )


def _finding(**overrides: object) -> MarkdownReportFinding:
    values = {
        "operational_rank": 1,
        "cve_id": "CVE-2026-0001",
        "priority": "High",
        "status": "open",
        "risk_score": 70.0,
        "epss": 0.42,
        "cvss_base_score": 8.1,
        "in_kev": False,
        "asset": "Payments API",
        "component": "demo-lib",
        "rationale": "Representative SARIF service fixture.",
        "recommended_action": "Patch demo-lib.",
        "data_quality_confidence": "high",
    }
    values.update(overrides)
    return MarkdownReportFinding(**values)  # type: ignore[arg-type]


def test_workbench_sarif_collects_nested_http_references_and_dedupes() -> None:
    finding = _finding(
        vulnerability={
            "references": [
                {"url": "https://vendor.example/advisories/CVE-2026-0001"},
                "https://duplicate.example/advisory",
                "ftp://ignored.example/advisory",
            ],
            "url": "https://single.example/advisory",
        },
        evidence={
            "reference_urls": [
                "https://duplicate.example/advisory",
                "http://osv.example/vulnerability/CVE-2026-0001",
            ],
            "href": "mailto:security@example.test",
        },
        explanation={
            "provider": [
                {"link": "https://nested.example/reference"},
                {"link": "https://duplicate.example/advisory"},
            ],
            "urls": ["../local-note"],
        },
    )

    sarif = render_sarif_report(_payload_with_findings([finding]))
    result = sarif["runs"][0]["results"][0]
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

    assert result["properties"]["references"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
        "https://vendor.example/advisories/CVE-2026-0001",
        "https://duplicate.example/advisory",
        "https://single.example/advisory",
        "http://osv.example/vulnerability/CVE-2026-0001",
        "https://nested.example/reference",
    ]
    assert rule["helpUri"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    assert rule["properties"]["references"] == result["properties"]["references"]


def test_workbench_sarif_hardens_artifact_uris_from_occurrence_evidence() -> None:
    unsafe = _finding(
        cve_id="CVE-2026-0002",
        occurrences=[
            {"evidence": {"path": "/private/input.csv"}},
            {"file": "../secret.txt"},
            {"evidence": {"artifact_uri": "https://example.test/input.csv"}},
            {"evidence": {"target_kind": "service", "target_ref": "payments-api"}},
        ],
    )
    windows_path = _finding(
        cve_id="CVE-2026-0003",
        occurrences=[{"evidence": {"path": r".\\src\\package-lock.json"}}],
    )
    fallback = _finding(
        cve_id="CVE-2026-0004",
        component_purl="pkg:npm/demo-lib@1.0.0",
        occurrences=[],
    )

    sarif = render_sarif_report(_payload_with_findings([unsafe, windows_path, fallback]))
    results = sarif["runs"][0]["results"]
    uris = [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in results
    ]

    assert uris == [
        "workbench-input",
        "src/package-lock.json",
        "pkg:npm/demo-lib@1.0.0",
    ]
    assert all("/private" not in uri and "../secret" not in uri for uri in uris)
