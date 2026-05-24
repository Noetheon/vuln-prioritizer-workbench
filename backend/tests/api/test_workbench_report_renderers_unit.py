from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import report_renderers as renderers
from app.services.report_models import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
    ReportVerificationError,
)


def _payload(
    findings: list[MarkdownReportFinding] | None = None,
    *,
    governance_rollups: dict[str, object] | None = None,
    detection_coverage: dict[str, object] | None = None,
    provider_snapshot: MarkdownProviderSnapshot | None = None,
    filename: str | None = None,
) -> MarkdownReportPayload:
    return MarkdownReportPayload(
        generated_at=datetime(2026, 5, 1, tzinfo=UTC),
        project_id="project-1",
        project_name="Payments",
        run_id="run-1",
        run_status="completed",
        input_type="generic-occurrence-csv",
        filename=filename,
        summary={},
        findings=findings or [],
        provider_snapshot=provider_snapshot,
        governance_rollups=governance_rollups or {},
        detection_coverage=detection_coverage or {},
    )


def _finding(**overrides: object) -> MarkdownReportFinding:
    values = {
        "operational_rank": 1,
        "cve_id": "CVE-2026-0001",
        "priority": "High",
        "status": "open",
        "risk_score": 70.0,
        "epss": 0.4,
        "cvss_base_score": 8.1,
        "in_kev": False,
        "asset": None,
        "component": "demo-lib",
        "rationale": "Representative renderer fixture.",
        "recommended_action": "Patch demo-lib.",
        "data_quality_confidence": "high",
    }
    values.update(overrides)
    return MarkdownReportFinding(**values)  # type: ignore[arg-type]


def test_markdown_and_html_reports_render_empty_states_without_snapshot() -> None:
    payload = _payload()

    markdown = renderers.render_markdown_report(payload)
    html = renderers.render_html_executive_report(payload)

    assert "No findings were recorded for this analysis run." in markdown
    assert "No rationale records are available for this analysis run." in markdown
    assert "No data quality records are available for this analysis run." in markdown
    assert "No provider snapshot was linked to this analysis run." in markdown
    assert "No findings were recorded for this analysis run." in html
    assert "No remediation recommendations are available for this run." in html
    assert "Confirm import coverage before treating this as a no-risk result." in html
    assert "No business service risk can be derived because no findings were recorded." in html
    assert "No provider snapshot was linked to this analysis run." in html


def test_governance_and_detection_exports_render_empty_and_minimal_branches() -> None:
    markdown_lines = renderers._markdown_governance_section({}, [])
    html = renderers._html_governance_rollups({}, [])
    empty_detection = renderers._governance_detection_coverage_export(
        _payload(detection_coverage={"summary": {"covered": 1}})
    )
    populated_detection = renderers._governance_detection_coverage_export(
        _payload(
            detection_coverage={
                "summary": {"covered": 1},
                "items": [{"technique_id": "T1059", "coverage_level": "partial"}],
            }
        )
    )

    assert "No service rollups are available for this analysis run." in markdown_lines
    assert "No asset rollups are available for this analysis run." in markdown_lines
    assert "| Owner | Unassigned | 0 | 0 | 0 | 0 | 0 |" in markdown_lines
    assert "Governance Exceptions" in html
    assert "No accepted-risk waiver debt is currently recorded for this run." in html
    assert empty_detection is None
    assert populated_detection is not None
    assert populated_detection["items"] == [{"technique_id": "T1059", "coverage_level": "partial"}]
    assert "not proof" in populated_detection["limitations"][0]


def test_verify_evidence_bundle_translates_archive_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail(_bundle_path: Path) -> tuple[object, object, list[object]]:
        raise ValueError("bad archive")

    monkeypatch.setattr(renderers, "verify_evidence_bundle_archive", fail)

    with pytest.raises(ReportVerificationError, match="bad archive"):
        renderers.verify_evidence_bundle_zip(tmp_path / "evidence.zip")


def test_report_renderer_small_helpers_cover_governance_and_fallback_branches() -> None:
    assert renderers._business_impact_summary(
        [_finding(asset="payments-api"), _finding(asset="worker")]
    ).startswith("Business exposure is concentrated")
    assert renderers._business_impact_summary([_finding(asset=None)]).startswith(
        "Asset and owner context is not complete"
    )
    assert (
        renderers._component_label(
            SimpleNamespace(component=SimpleNamespace(name="openssl", version=None))
        )
        == "openssl"
    )
    assert renderers._vulnerability_payload(SimpleNamespace(vulnerability=None)) == {}
    assert (
        renderers._decision_text(
            {"decision_statement": {"summary": "Patch now."}}, "decision_statement"
        )
        == "Patch now."
    )
    assert (
        renderers._decision_text(
            {"decision_statement": "   "},
            "decision_statement",
            fallback="Fallback.",
        )
        == "Fallback."
    )
    assert renderers._decision_sla({"sla": ""}) is None
    assert (
        renderers._decision_sla({"sla": {"label": "Emergency", "target_days": 3}})
        == "Emergency / 3d"
    )
    assert (
        renderers._decision_sla({"sla": {"label": "Custom", "target_hours": 1.5}})
        == "Custom / 1.5h"
    )
    assert renderers._flag_items([{"code": "missing", "message": "Provider missing"}, "raw"]) == [
        "missing - Provider missing",
        "raw",
    ]
    assert renderers._dict_list("not-a-list") == []


def test_report_renderer_boolish_and_vex_fallback_helpers() -> None:
    assert renderers._governance_decision_statement(
        finding=SimpleNamespace(
            waived=False,
            suppressed_by_vex=True,
            under_investigation=False,
        ),
        explanation={
            "vex_status": "under_investigation",
            "vex_source_format": "cyclonedx",
            "vex_source_record_id": "record-1",
        },
        base_statement=None,
    ) == (
        "Decision Statement: review finding governance. "
        "VEX governance applies (status under_investigation:1; source cyclonedx; record record-1)."
    )

    assert (
        renderers._boolish_signal(
            SimpleNamespace(explanation={"attack_mapped": False}, evidence={"attack_mapped": True}),
            "attack_mapped",
        )
        is True
    )
    assert (
        renderers._boolish_signal(
            SimpleNamespace(explanation={"waived": True}, evidence={}),
            "waived",
        )
        is True
    )
    assert renderers._vex_status_counts_from_explanation(
        {"vex_statuses": {"fixed": 2, "": 3, "affected": "yes"}}
    ) == renderers.Counter({"fixed": 2, "affected": 1})
    assert renderers._vex_status_counts_from_explanation(
        {"provenance": {"vex_status": "under_investigation"}}
    ) == renderers.Counter({"under_investigation": 1})


def test_executive_html_groups_campaigns_and_interprets_freshness() -> None:
    from bs4 import BeautifulSoup

    log4j_findings = [
        _finding(
            cve_id="CVE-2021-44228",
            priority="Critical",
            status="open",
            in_kev=True,
            epss=0.945,
            cvss_base_score=10.0,
            asset=f"identity-{index}",
            owner="team-identity",
            business_service="identity",
            environment="prod",
            exposure="internet-facing",
            decision_sla="Emergency / 24h",
            recommended_action="Upgrade affected log4j-core components.",
            explanation={"attack_techniques": ["T1190"]},
            attack_mapped=True,
        )
        for index in range(1, 6)
    ]
    log4j_findings.append(
        _finding(
            cve_id="CVE-2021-44228",
            priority="Critical",
            status="fixed",
            in_kev=True,
            epss=0.945,
            cvss_base_score=10.0,
            asset="warehouse-dr",
            owner="team-identity",
            business_service="identity",
            environment="prod",
            exposure="internal",
            decision_sla="Emergency / 24h",
            recommended_action="Retain fixed-state validation evidence.",
        )
    )
    spring_findings = [
        _finding(
            cve_id="CVE-2022-22965",
            priority="Critical",
            status="open",
            in_kev=True,
            epss=0.944,
            cvss_base_score=9.8,
            asset=f"catalog-{index}",
            owner="team-catalog",
            business_service="catalog",
            environment="prod",
            exposure="internet-facing",
            decision_sla="Emergency / 24h",
            recommended_action="Apply validated Spring Framework fixes.",
        )
        for index in range(1, 4)
    ]
    spring_findings.append(
        _finding(
            cve_id="CVE-2022-22965",
            priority="Critical",
            status="suppressed",
            in_kev=True,
            epss=0.944,
            cvss_base_score=9.8,
            asset="catalog-dr",
            owner="team-catalog",
            business_service="catalog",
            environment="dr",
            exposure="internal",
            suppressed_by_vex=True,
            recommended_action="Retain VEX evidence for suppressed DR node.",
        )
    )
    accepted = _finding(
        cve_id="CVE-2024-0001",
        priority="High",
        status="accepted",
        waived=True,
        asset="billing-worker",
        owner="risk-owner",
        business_service="billing",
        environment="prod",
        exposure="internal",
    )
    snapshot = MarkdownProviderSnapshot(
        id="provider-snapshot-1",
        content_hash="sha256:provider-fixture",
        nvd_last_sync="2026-04-29",
        epss_date="2026-04-15",
        kev_catalog_version="2026-01-01",
        source_hashes={"provider_snapshot": "sha256:provider-fixture"},
        source_metadata={"locked_provider_data": True, "selected_sources": ["nvd", "epss", "kev"]},
    )
    governance_rollups = {
        "waiver_debt": {
            "waiver_count": 1,
            "expired_count": 0,
            "review_due_count": 1,
            "expiring_soon_count": 0,
            "accepted_finding_count": 1,
            "items": [
                {
                    "scope": "billing-worker / CVE-2024-0001",
                    "owner": "risk-owner",
                    "status": "active",
                    "expires_at": "2026-06-01",
                    "review_at": "2026-04-30",
                    "matched_findings": 1,
                }
            ],
        }
    }
    payload = _payload(
        findings=[*log4j_findings, *spring_findings, accepted],
        governance_rollups=governance_rollups,
        provider_snapshot=snapshot,
        filename="demo_workspace_occurrences.csv",
    )

    html = renderers.render_html_executive_report(payload)
    soup = BeautifulSoup(html, "html.parser")

    headings = [heading.get_text(" ", strip=True) for heading in soup.select("h2")]
    assert "Decision Brief" in headings
    assert "Risk Posture Cards" in headings
    assert "First 24h and 7d Action Plan" in headings
    assert "Top Remediation Campaigns" in headings
    assert "Business Services at Risk" in headings
    assert "Governance Exceptions" in headings
    assert "Evidence Confidence and Provider Freshness" in headings

    campaigns = renderers._get_remediation_campaigns(payload.findings)
    assert [campaign["campaign_name"] for campaign in campaigns[:2]] == [
        "CVE-2021-44228 / Log4Shell",
        "CVE-2022-22965 / Spring4Shell",
    ]
    assert renderers._actionability_summary(log4j_findings) == "5 open, 1 fixed"
    assert renderers._actionability_summary(spring_findings) == "3 open, 1 suppressed"

    campaign_clusters = [
        row.select("td")[1].get_text(" ", strip=True)
        for row in soup.select('section[aria-labelledby="remediation-campaigns"] tbody tr')
    ]
    assert campaign_clusters.count("CVE-2021-44228 / Log4Shell") == 1
    assert campaign_clusters.count("CVE-2022-22965 / Spring4Shell") == 1

    recommendation_titles = [
        item.select_one("strong").get_text(" ", strip=True)
        for item in soup.select('section[aria-labelledby="recommendations"] li')
    ]
    assert recommendation_titles.count("CVE-2021-44228 / Log4Shell remediation campaign") == 1
    assert recommendation_titles.count("CVE-2022-22965 / Spring4Shell remediation campaign") == 1

    provider_rows = renderers._provider_freshness_rows(snapshot, payload.generated_at)
    provider_statuses = {row["signal"]: row["status"] for row in provider_rows}
    assert provider_statuses["NVD last sync"] == "Fresh"
    assert provider_statuses["EPSS date"] == "Warning"
    assert provider_statuses["KEV catalog version"] == "Stale"
    assert renderers._provider_freshness_status(snapshot, payload.generated_at) == "Stale"
    assert "+3 more" not in soup.get_text(" ", strip=True)
