from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import report_renderers as renderers
from app.services.report_models import (
    EvidencePackageArtifact,
    EvidencePackageContext,
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
    assert "no VEX suppressed findings" in html
    assert "attack-navigator-layer.json" in html
    assert "optional" in html
    lowered = html.lower()
    assert "<script" not in lowered
    assert "<link" not in lowered
    assert " src=" not in lowered
    assert "@import" not in lowered


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


def test_metric_tone_tracks_provider_freshness_value() -> None:
    from app.services.report_html_components import _html_metric

    assert 'data-tone="success"' in _html_metric("Provider Freshness", "Fresh")
    assert 'data-tone="warning"' in _html_metric("Provider Freshness", "Warning")
    assert 'data-tone="critical"' in _html_metric("Provider Freshness", "Stale")


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
    assert "Executive Risk Posture" in headings
    assert "First 24h and 7d Action Plan" in headings
    assert "Top Remediation Campaigns" in headings
    assert "Business Services at Risk" in headings
    assert "Governance Exceptions" in headings
    assert "Evidence Confidence and Provider Freshness" in headings
    assert "Evidence Package Contents" in headings
    assert "Decision Ready Recommendations" in headings
    assert "ATT&CK/TTP Context" in headings
    assert "Technical Appendix note" in headings

    campaigns = renderers._get_remediation_campaigns(payload.findings)
    assert [campaign["campaign_name"] for campaign in campaigns[:2]] == [
        "CVE-2021-44228 / Log4Shell",
        "CVE-2022-22965 / Spring4Shell",
    ]
    assert renderers._actionability_summary(log4j_findings) == "5 open, 1 fixed"
    assert renderers._actionability_summary(spring_findings) == "3 open, 1 suppressed"

    campaign_clusters = [
        row.select("td")[1].get_text(" ", strip=True)
        for row in soup.select('section[aria-labelledby="campaigns"] tbody tr')
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
    assert provider_statuses["Snapshot locked"] == "Reproducible"
    assert provider_statuses["Selected sources"] == "Recorded"
    assert provider_statuses["Source hashes"] == "Recorded"
    assert provider_statuses["Static HTML safety"] == "Controlled"
    assert provider_statuses["Evidence bundle manifest"] == "Expected"
    assert renderers._provider_freshness_status(snapshot, payload.generated_at) == "Stale"
    assert "+3 more" not in soup.get_text(" ", strip=True)

    view_model = renderers.build_executive_report_view_model(payload)
    assert view_model.risk_posture["emergency_sla_count"] == 2
    assert view_model.evidence_package[0]["artifact"] == "manifest.json"
    assert view_model.evidence_package[0]["status"] == "expected"
    assert view_model.technical_appendix["note"].startswith("Detailed finding rows")


def test_executive_view_model_separates_overlapping_actionability_states() -> None:
    findings = [
        _finding(cve_id="CVE-2026-0001", status="accepted", waived=True),
        _finding(cve_id="CVE-2026-0002", status="suppressed", suppressed_by_vex=True),
        _finding(cve_id="CVE-2026-0003", status="fixed", waived=True, suppressed_by_vex=True),
        _finding(
            cve_id="CVE-2026-0004",
            status="open",
            suppressed_by_vex=True,
            under_investigation=True,
            explanation={"vex_status": "under_investigation"},
        ),
        _finding(cve_id="CVE-2026-0005", status="open"),
    ]
    payload = _payload(findings=findings)

    view_model = renderers.build_executive_report_view_model(payload)

    assert view_model.risk_posture["total_findings"] == 5
    assert view_model.risk_posture["open_actionable_findings"] == 2
    assert view_model.risk_posture["accepted_risk_findings"] == 1
    assert view_model.risk_posture["vex_suppressed_findings"] == 1
    assert view_model.risk_posture["fixed_evidence_findings"] == 1
    assert view_model.governance_exceptions["under_investigation"] == 1


def test_campaign_grouping_uses_stable_action_priority_component_key() -> None:
    findings = [
        _finding(
            cve_id="CVE-2026-1000",
            priority="Critical",
            component="demo-lib 1.0.0",
            recommended_action="Upgrade demo-lib to 1.2.0.",
            asset="asset-a",
        ),
        _finding(
            cve_id="CVE-2026-1000",
            priority="Critical",
            component="demo-lib 1.0.1",
            recommended_action="Upgrade demo-lib to 1.2.0.",
            asset="asset-b",
        ),
        _finding(
            cve_id="CVE-2026-1000",
            priority="Critical",
            component="demo-lib 1.0.1",
            recommended_action="Disable exposed demo module.",
            asset="asset-c",
        ),
    ]

    campaigns = renderers._get_remediation_campaigns(findings)

    assert len(campaigns) == 2
    assert sorted(campaign["open_actionable_count"] for campaign in campaigns) == [1, 2]


def test_provider_freshness_needs_review_for_unknown_kev_version_semantics() -> None:
    snapshot = MarkdownProviderSnapshot(
        id="provider-snapshot-2",
        content_hash="sha256:provider-fixture",
        nvd_last_sync="2026-04-01",
        epss_date="2026-04-28",
        kev_catalog_version="kev-catalog-v2026.05",
        source_hashes={"kev": "sha256:kev"},
        source_metadata={"locked_provider_data": True, "selected_sources": ["kev"]},
    )

    rows = renderers._provider_freshness_rows(snapshot, datetime(2026, 5, 1, tzinfo=UTC))
    statuses = {row["signal"]: row["status"] for row in rows}

    assert statuses["Snapshot locked"] == "Reproducible"
    assert statuses["NVD last sync"] == "Fresh"
    assert statuses["EPSS date"] == "Fresh"
    assert statuses["KEV catalog version"] == "Needs Review"
    assert renderers._provider_freshness_status(snapshot, datetime(2026, 5, 1, tzinfo=UTC)) == (
        "Warning"
    )


def test_executive_html_uses_bundle_evidence_package_context() -> None:
    payload = _payload(findings=[_finding(cve_id="CVE-2026-3000")])
    evidence_context = EvidencePackageContext(
        mode="bundle",
        artifacts=[
            EvidencePackageArtifact(
                artifact="manifest.json",
                purpose="Bundle manifest and artifact hash verification.",
                status="included",
                note="Generated after artifact hashes are finalized.",
            ),
            EvidencePackageArtifact(
                artifact="analysis.json",
                purpose="Machine readable analysis export.",
                status="included",
                sha256="a" * 64,
                size_bytes=1234,
                kind="analysis-json",
            ),
            EvidencePackageArtifact(
                artifact="executive.html",
                purpose="Decision oriented executive brief.",
                status="included",
                note="Hash recorded in final manifest.json after this HTML is rendered.",
            ),
        ],
    )

    html = renderers.render_html_executive_report(
        payload,
        evidence_package_context=evidence_context,
    )
    view_model = renderers.build_executive_report_view_model(
        payload,
        evidence_package_context=evidence_context,
    )

    assert view_model.risk_posture["evidence_bundle_status"] == "Ready"
    assert view_model.evidence_package[1]["sha256"] == "a" * 64
    assert "1,234 bytes" in html
    assert "Hash recorded in final manifest.json" in html
    assert "Printable decision sign-off" in html
    assert "Approval outcome" in html


def test_attack_context_requires_reviewed_mapping_source_before_rendering_techniques() -> None:
    reviewed = _finding(
        cve_id="CVE-2026-2000",
        attack_mapped=True,
        explanation={
            "attack_context": {
                "mapped": True,
                "source": "local-curated",
                "review_status": "reviewed",
                "mappings": [
                    {
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application",
                    }
                ],
            }
        },
    )
    unknown_source = _finding(
        cve_id="CVE-2026-2001",
        attack_mapped=True,
        explanation={
            "attack_context": {
                "mapped": True,
                "source": "unknown",
                "review_status": "reviewed",
                "mappings": [{"technique_id": "T1059"}],
            }
        },
    )
    unmapped = _finding(cve_id="CVE-2026-2002", attack_mapped=False)
    payload = _payload(findings=[reviewed, unknown_source, unmapped])

    html = renderers.render_html_executive_report(payload)
    view_model = renderers.build_executive_report_view_model(payload)

    assert view_model.attack_context["mapped_techniques"] == [
        {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "source": "local-curated",
        }
    ]
    assert "T1190" in html
    assert "T1059" not in html
    assert "No LLM inferred mappings are used" in html
    assert "does not prove compromise" in html
    assert "does not override" in html


def test_render_safe_text_with_links() -> None:
    from app.services.report_html_helpers import render_safe_text_with_links

    # Safe links
    assert (
        render_safe_text_with_links("Patch [here](https://example.com) now.")
        == 'Patch <a href="https://example.com" target="_blank" '
        'rel="noopener noreferrer">here</a> now.'
    )
    assert (
        render_safe_text_with_links("Check [CISA](http://cisa.gov) details.")
        == 'Check <a href="http://cisa.gov" target="_blank" '
        'rel="noopener noreferrer">CISA</a> details.'
    )

    # Unsafe links (not http/https)
    assert (
        render_safe_text_with_links("Run [unsafe](javascript:alert(1)) code.")
        == "Run [unsafe](javascript:alert(1)) code."
    )
    assert (
        render_safe_text_with_links(
            "Load [data](data:text/html,<script>alert(1)</script>) content."
        )
        == "Load [data](data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;) content."
    )

    # XSS injection attempts
    assert (
        render_safe_text_with_links("<script>alert(1)</script>")
        == "&lt;script&gt;alert(1)&lt;/script&gt;"
    )
    assert (
        render_safe_text_with_links('<img src=x onerror="alert(1)">')
        == "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"
    )


def test_pluralization_grammar_decision_brief() -> None:
    from app.services.report_html_helpers import _executive_verdict_summary_helper

    # 1 finding, 1 KEV
    finding1 = _finding(cve_id="CVE-2026-0001", priority="Critical", in_kev=True, status="open")
    payload1 = _payload(findings=[finding1])
    verdict1 = _executive_verdict_summary_helper(payload1)
    assert "analyzed 1 finding from" in verdict1
    assert "1 finding is open and actionable" in verdict1
    assert "1 finding is KEV-backed" in verdict1

    # 2 findings, 2 KEV
    finding2 = _finding(cve_id="CVE-2026-0002", priority="Critical", in_kev=True, status="open")
    payload2 = _payload(findings=[finding1, finding2])
    verdict2 = _executive_verdict_summary_helper(payload2)
    assert "analyzed 2 findings from" in verdict2
    assert "2 findings are open and actionable" in verdict2
    assert "2 findings are KEV-backed" in verdict2


def test_executive_html_helper_edge_branches_are_decision_oriented() -> None:
    from app.services.report_html_governance import (
        _html_asset_rollup_row,
        _html_service_rollup_row,
        _html_waiver_debt_row,
    )
    from app.services.report_html_helpers import (
        _actionability_summary_helper,
        _calculate_age_and_verdict_helper,
        _campaign_ranking_rationale,
        _get_remediation_campaigns_helper,
        _html_business_impact_table_helper,
        _is_overdue_helper,
        _provider_status_class,
        _short_list,
        _technique_ids_for_findings,
        render_safe_text_with_links,
    )

    ref_date = datetime(2026, 5, 1, tzinfo=UTC)
    assert render_safe_text_with_links(None) == "N/A"
    assert _short_list([], noun="owner") == "N/A"
    assert _actionability_summary_helper([]) == "No findings"
    assert _is_overdue_helper("", ref_date) is False
    assert _is_overdue_helper("not-a-date", ref_date) is False
    assert _calculate_age_and_verdict_helper(None, ref_date) == (
        "N/A",
        "Unknown",
        "badge-neutral",
    )
    assert _calculate_age_and_verdict_helper("not-a-date", ref_date) == (
        "N/A",
        "Unknown",
        "badge-neutral",
    )
    assert _calculate_age_and_verdict_helper("2026-05-03", ref_date)[1] == "Fresh"
    assert _provider_status_class("Controlled") == "badge-success"
    assert _provider_status_class("unexpected") == "badge-neutral"

    accepted = _finding(
        cve_id="CVE-2026-0002",
        status="accepted",
        waived=True,
        business_service="risk",
        owner="risk-owner",
    )
    suppressed = _finding(
        cve_id="CVE-2026-0003",
        status="suppressed",
        suppressed_by_vex=True,
        business_service="risk",
        owner="risk-owner",
    )
    fixed = _finding(
        cve_id="CVE-2026-0004",
        status="fixed",
        business_service="closed",
        owner="ops-owner",
    )
    business_html = _html_business_impact_table_helper([accepted, suppressed, fixed])
    assert "Governance review" in business_html
    assert "Evidence validation" in business_html
    assert "VEX suppressed" in business_html

    nested_attack = _finding(
        attack_mapped=True,
        explanation={
            "attack_techniques": [{"technique_id": "T1190"}],
            "attack_context": {"techniques": [{"attack_object_id": "T1210"}]},
            "attack": {"techniques": ["T1499"]},
        },
    )
    assert _technique_ids_for_findings([nested_attack]) == ["T1190", "T1210", "T1499"]

    campaign = _get_remediation_campaigns_helper(
        [
            _finding(
                cve_id="CVE-2026-0005",
                status="open",
                in_kev=True,
                epss=0.2,
                cvss_base_score=9.1,
                environment="production",
                exposure="internal",
                criticality="critical",
            )
        ]
    )[0]
    assert _campaign_ranking_rationale(campaign).startswith("Internal production exposure")

    assert "Review now" in _html_waiver_debt_row(
        {"status": "expired", "matched_findings": 0},
        ref_date,
    )
    assert "Review before expiry" in _html_waiver_debt_row(
        {"status": "expiring_soon", "matched_findings": 0},
        ref_date,
    )
    assert "No immediate action" in _html_waiver_debt_row(
        {"status": "active", "matched_findings": 0, "review_at": "not-a-date"},
        ref_date,
    )
    assert "review due" in _html_waiver_debt_row(
        {"status": "active", "matched_findings": 1, "review_at": "2026-05-01"},
        ref_date,
    )
    assert "Accepted risk active" in _html_waiver_debt_row(
        {"status": "active", "matched_findings": 1},
        ref_date,
    )
    assert "Checkout" in _html_service_rollup_row(
        {"label": "Checkout", "risk_score_total": 12.5, "review_due_waiver_count": 1}
    )
    assert "checkout-api" in _html_asset_rollup_row(
        {"label": "checkout-api", "risk_score_total": 9, "suppressed_by_vex_count": 1}
    )
