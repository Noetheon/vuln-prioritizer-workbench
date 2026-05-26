from __future__ import annotations

import uuid
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from app import models as app_models
from app.services import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
    build_attack_navigator_layer_payload,
)
from utils.workbench_env import DEMO_CVE_LOG4SHELL, DEMO_CVE_XZ

VPW054_DEMO_ARTIFACTS = {
    "markdown": Path("docs/examples/vpw-054-workbench-technical-report.md"),
    "html": Path("docs/examples/vpw-054-workbench-executive-report.html"),
    "json": Path("docs/examples/vpw-054-workbench-analysis-result.v1.json"),
}
VPW054_HTML_SNAPSHOT = Path("backend/tests/api/snapshots/vpw_054_executive_report.normalized.html")
VPW068_MARKDOWN_SNAPSHOT = Path("backend/tests/api/snapshots/vpw_068_governance_report.md")
VPW068_HTML_SNAPSHOT = Path("backend/tests/api/snapshots/vpw_068_governance_report.normalized.html")
VPW054_SECRET_MARKERS = (
    "super-secret-token",
    "provider-secret-key",
    "bearer ",
    "api_key",
    "authorization",
    "/users/",
    "/tmp/",
    ".env",
)

_T = TypeVar("_T")


def replace(instance: _T, /, **changes: Any) -> _T:
    """Copy either a Pydantic report model or a legacy dataclass fixture."""
    model_copy = getattr(instance, "model_copy", None)
    if callable(model_copy):
        return model_copy(update=changes)
    return dataclass_replace(instance, **changes)


def _vpw060_snapshot_layer() -> dict[str, Any]:
    project_id = uuid.UUID("00000000-0000-4000-8000-000000000060")
    run_id = uuid.UUID("00000000-0000-4000-8000-000000000061")
    finding_id = uuid.UUID("00000000-0000-4000-8000-000000000062")
    vulnerability_id = uuid.UUID("00000000-0000-4000-8000-000000000063")
    generated_at = datetime(2026, 4, 29, 12, 0, tzinfo=UTC)
    finding = app_models.Finding(
        id=finding_id,
        project_id=project_id,
        vulnerability_id=vulnerability_id,
        cve_id=DEMO_CVE_LOG4SHELL,
        dedup_key="vpw060-log4shell",
        priority=app_models.FindingPriority.HIGH,
        priority_rank=2,
        operational_rank=1,
        risk_score=94.2,
        in_kev=True,
        attack_mapped=True,
    )
    unmapped = app_models.Finding(
        id=uuid.UUID("00000000-0000-4000-8000-000000000064"),
        project_id=project_id,
        vulnerability_id=uuid.UUID("00000000-0000-4000-8000-000000000065"),
        cve_id=DEMO_CVE_XZ,
        dedup_key="vpw060-xz",
        priority=app_models.FindingPriority.CRITICAL,
        priority_rank=1,
        operational_rank=2,
        risk_score=100.0,
        in_kev=False,
        attack_mapped=False,
    )
    context = app_models.FindingAttackContext(
        id=uuid.UUID("00000000-0000-4000-8000-000000000066"),
        finding_id=finding.id,
        analysis_run_id=run_id,
        cve_id=finding.cve_id,
        mapped=True,
        source="local-curated",
        review_status="needs_review",
        defensive_note="Defensive triage context only.",
        rationale="Reviewed local mapping for defensive prioritization.",
        technique_ids_json=["T1190"],
        tactic_ids_json=["initial-access"],
        mappings_json=[
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "attack_object_id": "T1190",
                "attack_object_name": "Exploit Public-Facing Application",
                "tactics": ["initial-access"],
                "confidence": "low",
                "review_status": "needs_review",
                "source": "local-curated",
                "mapping_type": "exploitation",
                "defensive_note": "Use for defensive triage and coverage review.",
                "rationale": "Reviewed local mapping; no procedural detail included.",
            }
        ],
        created_at=generated_at,
        updated_at=generated_at,
    )
    return build_attack_navigator_layer_payload(
        project_id=project_id,
        project_name="VPW-060 Snapshot",
        run_id=run_id,
        findings=[finding, unmapped],
        attack_contexts=[context],
        filter_value="all",
        generated_at=generated_at,
    )


def _vpw050_snapshot_payload() -> MarkdownReportPayload:
    return MarkdownReportPayload(
        generated_at=datetime(2026, 4, 29, 12, 0, tzinfo=UTC),
        project_id="00000000-0000-4000-8000-000000000156",
        project_name="VPW-050 Snapshot",
        run_id="00000000-0000-4000-8000-000000000050",
        run_status="completed",
        input_type="cve-list",
        filename="known-cves.txt",
        summary={"finding_count": 2, "counts_by_priority": {"Critical": 1, "High": 1}},
        findings=[
            MarkdownReportFinding(
                id="00000000-0000-4000-8000-000000000501",
                dedup_key="vpw050-xz",
                operational_rank=1,
                cve_id=DEMO_CVE_XZ,
                priority="critical",
                priority_rank=1,
                status="open",
                risk_score=100.0,
                epss=0.846,
                cvss_base_score=10.0,
                in_kev=False,
                attack_mapped=False,
                asset="Payments API",
                asset_key="payments-api",
                owner="platform-team",
                business_service="checkout",
                environment="prod",
                exposure="internet-facing",
                criticality="critical",
                component="xz 5.6.0-r0",
                component_purl="pkg:apk/alpine/xz@5.6.0-r0",
                vulnerability={"severity": "CRITICAL", "provider": {"nvd": "locked"}},
                rationale="Internet-facing production asset with critical score.",
                recommended_action="Patch [open](javascript:alert(1)) now.",
                data_quality_confidence="high",
                decision_statement=(
                    "Decision Statement: patch CVE-2024-3094 on Payments API "
                    "within the emergency SLA."
                ),
                business_impact="Checkout traffic depends on the affected service.",
                decision_sla="Emergency / 24h",
                explanation={
                    "decision_guidance": {
                        "recommendation_label": "Patch",
                        "decision_statement": (
                            "Decision Statement: patch CVE-2024-3094 on Payments API "
                            "within the emergency SLA."
                        ),
                    }
                },
                data_quality={"confidence": "high", "flags": []},
                evidence={"source": "snapshot"},
                occurrences=[
                    {
                        "id": "00000000-0000-4000-8000-000000000601",
                        "analysis_run_id": "00000000-0000-4000-8000-000000000050",
                        "source": "cve-list",
                        "raw_reference": DEMO_CVE_XZ,
                        "evidence": {"line": 1},
                    }
                ],
                data_quality_flags=[],
                first_seen_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
                last_seen_at=datetime(2026, 4, 29, 11, 30, tzinfo=UTC),
                created_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
                updated_at=datetime(2026, 4, 29, 11, 30, tzinfo=UTC),
            ),
            MarkdownReportFinding(
                id="00000000-0000-4000-8000-000000000502",
                dedup_key="vpw050-log4shell",
                operational_rank=2,
                cve_id=DEMO_CVE_LOG4SHELL,
                priority="high",
                priority_rank=2,
                status="in_review",
                risk_score=94.2,
                epss=0.944,
                cvss_base_score=10.0,
                in_kev=True,
                attack_mapped=True,
                asset="Ops API",
                asset_key="ops-api",
                owner="secops",
                business_service="operations",
                environment="prod",
                exposure="internal",
                criticality="high",
                component="log4j-core 2.14.1",
                component_purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                vulnerability={"severity": "CRITICAL", "provider": {"kev": True}},
                rationale="CISA KEV listing and vulnerable component evidence.",
                recommended_action="Patch via vendor upgrade.",
                data_quality_confidence="medium",
                decision_statement="Decision Statement: patch after owner validation.",
                business_impact="Operational tooling exposure requires management visibility.",
                decision_sla="Emergency / 24h",
                explanation={
                    "decision_guidance": {
                        "recommendation_label": "Patch",
                        "decision_statement": "Decision Statement: patch after owner validation.",
                    },
                    "attack_techniques": ["T1190"],
                },
                data_quality={
                    "confidence": "medium",
                    "flags": [{"code": "missing_asset_owner", "message": "Owner is not set"}],
                },
                evidence={"source": "snapshot"},
                occurrences=[
                    {
                        "id": "00000000-0000-4000-8000-000000000602",
                        "analysis_run_id": "00000000-0000-4000-8000-000000000050",
                        "source": "cve-list",
                        "raw_reference": DEMO_CVE_LOG4SHELL,
                        "evidence": {"line": 2},
                    }
                ],
                data_quality_flags=["missing_asset_owner - Owner is not set"],
                first_seen_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
                last_seen_at=datetime(2026, 4, 29, 11, 30, tzinfo=UTC),
                created_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
                updated_at=datetime(2026, 4, 29, 11, 30, tzinfo=UTC),
            ),
        ],
        provider_snapshot=MarkdownProviderSnapshot(
            id="00000000-0000-4000-8000-000000000650",
            content_hash="sha256:vpw050-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            created_at="2026-04-28T10:20:00Z",
            source_hashes={"provider_snapshot": "sha256:vpw050-snapshot"},
            source_metadata={
                "locked_provider_data": True,
                "selected_sources": ["nvd", "epss", "kev"],
            },
        ),
        project_description="Snapshot project for VPW-050 exports.",
        project_created_at=datetime(2026, 4, 29, 10, 0, tzinfo=UTC),
        project_updated_at=datetime(2026, 4, 29, 10, 30, tzinfo=UTC),
        run_started_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
        run_finished_at=datetime(2026, 4, 29, 11, 45, tzinfo=UTC),
        run_errors={},
    )


def _vpw054_demo_payload() -> MarkdownReportPayload:
    payload = _vpw050_snapshot_payload()
    xz_open = replace(
        payload.findings[0],
        id="00000000-0000-4000-8000-000000000541",
        dedup_key="vpw054-xz-payments-open",
        operational_rank=2,
        status="open",
        asset="Payments API",
        asset_key="payments-api",
        owner="platform-team",
        business_service="checkout",
        environment="prod",
        exposure="internet-facing",
        recommended_action="Upgrade xz package to the validated distro-fixed build.",
        decision_statement=(
            "Decision Statement: approve emergency remediation for CVE-2024-3094 "
            "on the internet-facing Payments API."
        ),
        explanation={
            **payload.findings[0].explanation,
            "attack_context": {"mapped": False, "source": None, "review_status": "unmapped"},
        },
    )
    log4shell_open = replace(
        payload.findings[1],
        id="00000000-0000-4000-8000-000000000542",
        dedup_key="vpw054-log4shell-identity-open",
        operational_rank=1,
        priority="critical",
        priority_rank=1,
        status="open",
        asset="Identity Gateway",
        asset_key="identity-gateway",
        owner="identity-team",
        business_service="identity",
        environment="prod",
        exposure="internet-facing",
        criticality="critical",
        recommended_action="Upgrade log4j-core to 2.17.2 and redeploy Identity Gateway.",
        decision_statement=(
            "Decision Statement: approve emergency remediation for Log4Shell on "
            "Identity Gateway and require clean re-import evidence."
        ),
        explanation={
            **payload.findings[1].explanation,
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
            },
        },
    )
    log4shell_fixed = replace(
        payload.findings[1],
        id="00000000-0000-4000-8000-000000000543",
        dedup_key="vpw054-log4shell-ops-fixed",
        operational_rank=7,
        priority="critical",
        priority_rank=1,
        status="fixed",
        asset="Ops API",
        asset_key="ops-api",
        owner="secops",
        business_service="operations",
        environment="prod",
        exposure="internal",
        recommended_action="Retain fixed-state validation evidence for Log4Shell.",
        decision_statement=(
            "Decision Statement: keep fixed evidence visible for the closed Ops API scope."
        ),
        explanation={
            **payload.findings[1].explanation,
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
            },
        },
    )
    accepted_risk = replace(
        payload.findings[0],
        id="00000000-0000-4000-8000-000000000544",
        dedup_key="vpw054-php-billing-accepted",
        operational_rank=4,
        cve_id="CVE-2024-4577",
        priority="high",
        priority_rank=3,
        status="accepted",
        risk_score=72.5,
        epss=0.037,
        cvss_base_score=9.8,
        in_kev=True,
        waived=True,
        attack_mapped=False,
        asset="Billing Worker",
        asset_key="billing-worker",
        owner="risk-owner",
        business_service="billing",
        environment="prod",
        exposure="internal",
        criticality="medium",
        component="php-cgi 8.2.18",
        component_purl="pkg:generic/php-cgi@8.2.18",
        recommended_action="Review accepted risk and replace the temporary compensating control.",
        decision_statement=(
            "Decision Statement: review accepted risk for CVE-2024-4577 before sign-off."
        ),
        explanation={
            "waiver": {
                "waiver_id": "00000000-0000-4000-8000-000000000545",
                "waiver_status": "review_due",
                "waiver_owner": "risk-owner",
                "waiver_expires_on": "2026-05-07",
                "waiver_review_on": "2026-04-29",
                "waiver_scope": "service:billing",
                "waiver_approval_ref": "CAB-054",
            },
            "waiver_status": "review_due",
            "waiver_owner": "risk-owner",
            "waiver_expires_on": "2026-05-07",
            "waiver_review_on": "2026-04-29",
        },
    )
    vex_suppressed = replace(
        payload.findings[0],
        id="00000000-0000-4000-8000-000000000546",
        dedup_key="vpw054-http2-edge-vex",
        operational_rank=5,
        cve_id="CVE-2023-44487",
        priority="high",
        priority_rank=4,
        status="suppressed",
        risk_score=41.0,
        epss=0.018,
        cvss_base_score=7.5,
        in_kev=False,
        suppressed_by_vex=True,
        attack_mapped=False,
        asset="Edge Proxy",
        asset_key="edge-proxy",
        owner="edge-team",
        business_service="edge ingress",
        environment="prod",
        exposure="internet-facing",
        criticality="high",
        component="nginx 1.25",
        component_purl="pkg:generic/nginx@1.25",
        recommended_action="Retain VEX evidence and reopen if affected HTTP/2 module is enabled.",
        decision_statement=(
            "Decision Statement: retain VEX evidence for CVE-2023-44487 edge scope."
        ),
        explanation={
            "vex_status": "not_affected",
            "vex_statuses": {"not_affected": 1},
            "vex_justification": "vulnerable_code_not_in_execute_path",
            "vex_source_format": "openvex",
            "vex_source_record_id": "VEX-054-EDGE",
        },
    )
    under_investigation = replace(
        payload.findings[0],
        id="00000000-0000-4000-8000-000000000547",
        dedup_key="vpw054-moveit-investigation",
        operational_rank=3,
        cve_id="CVE-2023-34362",
        priority="critical",
        priority_rank=2,
        status="open",
        risk_score=88.0,
        epss=0.911,
        cvss_base_score=9.8,
        in_kev=True,
        suppressed_by_vex=True,
        under_investigation=True,
        attack_mapped=False,
        asset="File Transfer Gateway",
        asset_key="file-transfer-gateway",
        owner="soc-team",
        business_service="partner file transfer",
        environment="prod",
        exposure="external",
        criticality="critical",
        component="moveit-transfer 2023.0",
        component_purl="pkg:generic/moveit-transfer@2023.0",
        recommended_action=(
            "Investigate VEX under-investigation status, validate exposure and patch if affected."
        ),
        decision_statement=(
            "Decision Statement: keep CVE-2023-34362 actionable until "
            "investigation evidence closes."
        ),
        explanation={
            "vex_status": "under_investigation",
            "vex_statuses": {"under_investigation": 1},
            "vex_source_format": "openvex",
            "vex_source_record_id": "VEX-054-MOVEIT",
        },
    )
    fixed_evidence = replace(
        payload.findings[1],
        id="00000000-0000-4000-8000-000000000548",
        dedup_key="vpw054-spring-fixed",
        operational_rank=6,
        cve_id="CVE-2022-22965",
        priority="high",
        priority_rank=5,
        status="fixed",
        risk_score=0.0,
        epss=0.024,
        cvss_base_score=9.8,
        in_kev=True,
        attack_mapped=False,
        asset="Catalog API",
        asset_key="catalog-api",
        owner="catalog-team",
        business_service="catalog",
        environment="prod",
        exposure="internal",
        criticality="high",
        component="spring-framework 5.3.18",
        component_purl="pkg:maven/org.springframework/spring-core@5.3.18",
        recommended_action="Retain fixed evidence for Spring4Shell closure.",
        decision_statement="Decision Statement: keep fixed evidence available for audit closure.",
        explanation={},
    )
    provider_snapshot = None
    if payload.provider_snapshot is not None:
        provider_snapshot = replace(
            payload.provider_snapshot,
            id="00000000-0000-4000-8000-000000000654",
            content_hash="sha256:vpw054-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-15",
            kev_catalog_version="kev-catalog-v2026.04",
            source_hashes={
                "nvd": "sha256:vpw054-nvd",
                "epss": "sha256:vpw054-epss",
                "kev": "sha256:vpw054-kev",
                "provider_snapshot": "sha256:vpw054-snapshot",
            },
        )
    return replace(
        payload,
        project_id="00000000-0000-4000-8000-000000000054",
        project_name="VPW-054 Demo Reports",
        project_description="Committed demo artifacts for VPW-054 report snapshot coverage.",
        run_id="00000000-0000-4000-8000-000000000540",
        filename="vpw-054-known-cves.txt",
        summary={"finding_count": 7, "counts_by_priority": {"Critical": 3, "High": 4}},
        findings=[
            log4shell_open,
            xz_open,
            under_investigation,
            accepted_risk,
            vex_suppressed,
            fixed_evidence,
            log4shell_fixed,
        ],
        provider_snapshot=provider_snapshot,
        governance_rollups={
            "project_id": "00000000-0000-4000-8000-000000000054",
            "generated_at": "2026-04-29T12:00:00Z",
            "owners": [
                _vpw068_rollup(
                    "owner",
                    "identity-team",
                    finding_count=1,
                    open_count=1,
                    critical_count=1,
                    kev_count=1,
                    attack_mapped_count=1,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
                _vpw068_rollup(
                    "owner",
                    "platform-team",
                    finding_count=1,
                    open_count=1,
                    critical_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "owner",
                    "risk-owner",
                    finding_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    high_count=1,
                    kev_count=1,
                    risk_score_total=72.5,
                    top_cves=["CVE-2024-4577"],
                ),
            ],
            "services": [
                _vpw068_rollup(
                    "service",
                    "identity",
                    finding_count=2,
                    open_count=1,
                    fixed_count=1,
                    critical_count=2,
                    kev_count=2,
                    attack_mapped_count=2,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
                _vpw068_rollup(
                    "service",
                    "checkout",
                    finding_count=1,
                    open_count=1,
                    critical_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "service",
                    "billing",
                    finding_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    high_count=1,
                    kev_count=1,
                    risk_score_total=72.5,
                    top_cves=["CVE-2024-4577"],
                ),
            ],
            "top_services_by_risk": [
                _vpw068_rollup(
                    "service",
                    "identity",
                    finding_count=2,
                    open_count=1,
                    fixed_count=1,
                    critical_count=2,
                    kev_count=2,
                    attack_mapped_count=2,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                )
            ],
            "assets": [
                _vpw068_rollup(
                    "asset",
                    "identity-gateway",
                    finding_count=1,
                    open_count=1,
                    critical_count=1,
                    kev_count=1,
                    attack_mapped_count=1,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
                _vpw068_rollup(
                    "asset",
                    "payments-api",
                    finding_count=1,
                    open_count=1,
                    critical_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "asset",
                    "billing-worker",
                    finding_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    high_count=1,
                    kev_count=1,
                    risk_score_total=72.5,
                    top_cves=["CVE-2024-4577"],
                ),
            ],
            "environments": [
                _vpw068_rollup(
                    "environment",
                    "prod",
                    finding_count=7,
                    open_count=3,
                    accepted_count=1,
                    fixed_count=2,
                    suppressed_count=1,
                    critical_count=3,
                    high_count=4,
                    kev_count=5,
                    attack_mapped_count=2,
                    suppressed_by_vex_count=1,
                    under_investigation_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=395.7,
                    top_cves=[
                        DEMO_CVE_LOG4SHELL,
                        DEMO_CVE_XZ,
                        "CVE-2023-34362",
                        "CVE-2024-4577",
                    ],
                )
            ],
            "top_assets_by_risk": [
                _vpw068_rollup(
                    "asset",
                    "payments-api",
                    finding_count=1,
                    open_count=1,
                    critical_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                )
            ],
            "waiver_debt": {
                "waiver_count": 1,
                "active_count": 0,
                "review_due_count": 1,
                "expired_count": 0,
                "expiring_soon_count": 1,
                "matched_finding_count": 1,
                "accepted_finding_count": 1,
                "expired_finding_count": 0,
                "review_due_finding_count": 1,
                "owner_counts": {"risk-owner": 1},
                "service_counts": {"billing": 1},
                "items": [
                    {
                        "id": "00000000-0000-4000-8000-000000000545",
                        "owner": "risk-owner",
                        "scope": "service:billing",
                        "status": "review_due",
                        "days_remaining": 8,
                        "expires_at": "2026-05-07",
                        "review_at": "2026-04-29",
                        "matched_findings": 1,
                        "cve_id": "CVE-2024-4577",
                        "service": "billing",
                        "asset_key": "billing-worker",
                        "finding_id": "00000000-0000-4000-8000-000000000544",
                    }
                ],
            },
        },
    )


def _vpw051_snapshot_payload() -> MarkdownReportPayload:
    payload = _vpw050_snapshot_payload()
    input_sha256 = "a" * 64
    first_finding = replace(
        payload.findings[0],
        recommended_action="Patch after using super-secret-token in the approval system.",
        rationale="Review local evidence from /tmp/pytest/vpw-051-input.txt.",
        evidence={
            "source": "snapshot",
            "authorization": "Bearer super-secret-token",
            "upload_path": "/tmp/pytest/vpw-051-input.txt",
        },
    )
    provider_snapshot = None
    if payload.provider_snapshot is not None:
        provider_snapshot = replace(
            payload.provider_snapshot,
            source_metadata={
                **payload.provider_snapshot.source_metadata,
                "source_path": "/Users/umut/private/provider-snapshot.json",
                "api_key": "provider-secret-key",
                "cache_dir": "/Users/umut/private/cache",
            },
        )
    return replace(
        payload,
        summary={
            **payload.summary,
            "input_sha256": input_sha256,
            "input_upload": {
                "original_filename": "known-cves.txt",
                "stored_filename": "known-cves.txt",
                "size_bytes": 29,
                "sha256": input_sha256,
                "path": "/Users/umut/private/vpw-051-input.txt",
                "token": "super-secret-token",
            },
        },
        run_error="Bearer super-secret-token",
        run_errors={"authorization": "Bearer super-secret-token"},
        findings=[first_finding, *payload.findings[1:]],
        provider_snapshot=provider_snapshot,
    )


def _vpw068_governance_payload() -> MarkdownReportPayload:
    payload = _vpw050_snapshot_payload()
    waiver = {
        "source": "workbench-api",
        "waiver_id": "00000000-0000-4000-8000-000000000681",
        "waiver_status": "review_due",
        "waiver_owner": "risk-team",
        "waiver_expires_on": "2026-05-07",
        "waiver_review_on": "2026-04-30",
        "waiver_scope": "service:checkout",
        "waiver_approval_ref": "CAB-068",
    }
    accepted = replace(
        payload.findings[0],
        status="accepted",
        waived=True,
        explanation={
            **payload.findings[0].explanation,
            "waiver": waiver,
            "waiver_status": "review_due",
            "waiver_owner": "risk-team",
            "waiver_expires_on": "2026-05-07",
            "waiver_review_on": "2026-04-30",
        },
        decision_statement=(
            "Decision Statement: maintain accepted risk for CVE-2024-3094 until "
            "owner review completes. Accepted-risk governance remains visible "
            "(owner risk-team; status review_due; review 2026-04-30; expires 2026-05-07)."
        ),
    )
    vex_suppressed = replace(
        payload.findings[1],
        status="suppressed",
        suppressed_by_vex=True,
        explanation={
            **payload.findings[1].explanation,
            "provenance": {
                "vex_statuses": {"not_affected": 1},
                "occurrences": [
                    {
                        "vex_status": "not_affected",
                        "source_format": "openvex",
                        "source_record_id": "VEX-068-1",
                    }
                ],
            },
            "vex_justification": "component_not_present",
            "vex_action_statement": "Reopen if the affected package is redeployed.",
            "vex_source_format": "openvex",
            "vex_source_record_id": "VEX-068-1",
        },
        decision_statement=(
            "Decision Statement: monitor VEX-suppressed CVE-2021-44228. "
            "VEX governance applies (status not_affected; source openvex; record VEX-068-1)."
        ),
    )
    return replace(
        payload,
        findings=[accepted, vex_suppressed],
        governance_rollups={
            "project_id": payload.project_id,
            "generated_at": "2026-04-29T12:00:00Z",
            "owners": [
                _vpw068_rollup(
                    "owner",
                    "platform-team",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "owner",
                    "secops",
                    finding_count=1,
                    high_count=1,
                    suppressed_count=1,
                    suppressed_by_vex_count=1,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
            ],
            "services": [
                _vpw068_rollup(
                    "service",
                    "checkout",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "service",
                    "operations",
                    finding_count=1,
                    high_count=1,
                    suppressed_count=1,
                    suppressed_by_vex_count=1,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
            ],
            "assets": [
                _vpw068_rollup(
                    "asset",
                    "payments-api",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "asset",
                    "ops-api",
                    finding_count=1,
                    high_count=1,
                    suppressed_count=1,
                    suppressed_by_vex_count=1,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
            ],
            "environments": [
                _vpw068_rollup(
                    "environment",
                    "prod",
                    finding_count=2,
                    critical_count=1,
                    high_count=1,
                    accepted_count=1,
                    suppressed_count=1,
                    waived_count=1,
                    suppressed_by_vex_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=194.2,
                    top_cves=[DEMO_CVE_XZ, DEMO_CVE_LOG4SHELL],
                )
            ],
            "top_services_by_risk": [
                _vpw068_rollup(
                    "service",
                    "checkout",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                )
            ],
            "top_assets_by_risk": [
                _vpw068_rollup(
                    "asset",
                    "payments-api",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                )
            ],
            "waiver_debt": {
                "waiver_count": 1,
                "active_count": 0,
                "review_due_count": 1,
                "expired_count": 0,
                "expiring_soon_count": 1,
                "matched_finding_count": 2,
                "accepted_finding_count": 1,
                "expired_finding_count": 0,
                "review_due_finding_count": 1,
                "owner_counts": {"risk-team": 1},
                "service_counts": {"checkout": 1},
                "items": [
                    {
                        "id": "00000000-0000-4000-8000-000000000681",
                        "owner": "risk-team",
                        "scope": "service:checkout",
                        "status": "review_due",
                        "days_remaining": 7,
                        "expires_at": "2026-05-07",
                        "review_at": "2026-04-30",
                        "matched_findings": 2,
                        "cve_id": None,
                        "service": "checkout",
                        "asset_key": None,
                        "finding_id": None,
                    }
                ],
            },
        },
    )


def _vpw068_rollup(
    dimension: str,
    label: str,
    *,
    finding_count: int,
    risk_score_total: float,
    top_cves: list[str],
    open_count: int = 0,
    accepted_count: int = 0,
    fixed_count: int = 0,
    suppressed_count: int = 0,
    critical_count: int = 0,
    high_count: int = 0,
    kev_count: int = 0,
    attack_mapped_count: int = 0,
    suppressed_by_vex_count: int = 0,
    under_investigation_count: int = 0,
    waived_count: int = 0,
    expired_waiver_count: int = 0,
    review_due_waiver_count: int = 0,
) -> dict[str, Any]:
    return {
        "dimension": dimension,
        "label": label,
        "finding_count": finding_count,
        "open_count": open_count,
        "accepted_count": accepted_count,
        "fixed_count": fixed_count,
        "suppressed_count": suppressed_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "kev_count": kev_count,
        "attack_mapped_count": attack_mapped_count,
        "suppressed_by_vex_count": suppressed_by_vex_count,
        "under_investigation_count": under_investigation_count,
        "waived_count": waived_count,
        "expired_waiver_count": expired_waiver_count,
        "review_due_waiver_count": review_due_waiver_count,
        "risk_score_total": risk_score_total,
        "risk_score_max": risk_score_total,
        "highest_priority": "Critical" if critical_count else "High" if high_count else None,
        "priority_counts": {
            "Critical": critical_count,
            "High": high_count,
            "Medium": 0,
            "Low": 0,
        },
        "status_counts": {
            "open": open_count,
            "in_review": 0,
            "remediating": 0,
            "fixed": fixed_count,
            "accepted": accepted_count,
            "suppressed": suppressed_count,
        },
        "top_cves": top_cves,
    }
