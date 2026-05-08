from __future__ import annotations

from types import SimpleNamespace

import pytest

from vuln_prioritizer import reporting_executive_model as model


def test_executive_model_branch_helpers_cover_fallbacks_and_limits() -> None:
    assert model._kpi_value({"kpis": [{"label": "Findings", "value": 2}]}, "Missing") == "0"
    points = model._scatter_points(
        [
            {"cve_id": "CVE-2026-0001", "cvss_base_score": None, "epss": 0.5},
            {"cve_id": "CVE-2026-0002", "cvss_base_score": 9.8, "epss": None},
            {
                "cve_id": "CVE-2026-0003",
                "cvss_base_score": 9.8,
                "epss": 0.9,
                "priority_label": "Critical",
                "in_kev": True,
            },
        ]
    )
    assert len(points) == 1
    assert points[0] == {
        "cve": "CVE-2026-0003",
        "cvss": 9.8,
        "epss": 0.9,
        "x": 392.0,
        "y": pytest.approx(16.8),
        "tone": "critical",
        "kev": True,
    }

    notes = model._attack_finding_notes(
        [
            {"attack_note": "first"},
            {"attack_rationale": "second"},
            {"attack_note": "first"},
            {"attack_note": "third"},
            {"attack_note": "fourth"},
        ]
    )
    assert notes == ["first", "second", "third"]


def test_executive_model_attack_and_confidence_branches() -> None:
    findings = [
        {
            "cve_id": "CVE-2026-0001",
            "attack_mapped": True,
            "attack_tactics": ["Initial Access"],
            "attack_techniques": ["T1190"],
            "priority_label": "Critical",
            "provenance": {
                "occurrences": [
                    {
                        "asset_business_service": "payments",
                        "asset_id": "asset-1",
                    }
                ]
            },
        },
        {
            "cve_id": "CVE-2026-0002",
            "attack_mapped": True,
            "attack_tactics": ["Execution"],
            "attack_techniques": [],
            "priority_label": "High",
            "provenance": {"occurrences": []},
        },
    ]
    matrix = model._attack_asset_matrix_model(
        findings,
        model.Counter({"Initial Access": 1, "Execution": 1}),
    )
    mapped = model._attack_top_mapped_findings(
        [
            {
                "cve_id": f"CVE-2026-10{index:02d}",
                "attack_mapped": True,
                "attack_techniques": ["T1190"],
                "attack_tactics": ["Initial Access"],
                "priority_label": "High",
                "priority_rank": 2,
            }
            for index in range(8)
        ]
    )
    confidence = model._mapping_confidence_model(
        [
            {"attack_mapped": True, "attack_mappings": ["skip", {"confidence": "high"}]},
            {"attack_mapped": True, "attack_mappings": [{"confidence": "medium"}]},
        ]
    )

    assert matrix["columns"] == ["payments"]
    assert matrix["rows"][0]["cells"] == [{"group": "payments", "count": 1}]
    assert len(mapped) == 6
    assert mapped[0]["technique"] == "T1190"
    assert confidence["available"] is True
    assert confidence["total"] == 2
    assert [row["label"] for row in confidence["rows"]] == ["High", "Medium"]


def test_executive_model_finding_route_status_and_vex_branches() -> None:
    service_only = {
        "cve_id": "CVE-2026-0003",
        "priority_label": "High",
        "provenance": {"occurrences": [{"asset_business_service": "billing"}]},
    }
    owner_only = {
        "cve_id": "CVE-2026-0004",
        "priority_label": "Medium",
        "provenance": {"occurrences": [{"asset_owner": "team-platform"}]},
    }
    asset_only = {
        "cve_id": "CVE-2026-0005",
        "priority_label": "Low",
        "provenance": {"asset_ids": ["asset-42"], "occurrences": []},
    }

    assert model._finding_row(service_only)["asset_service"] == "billing"
    assert model._finding_row(asset_only)["asset_service"] == "asset-42"
    assert model._route_label(service_only) == "billing"
    assert model._route_label(owner_only) == "team-platform"
    assert model._route_label({}) == "not supplied"
    assert model._status({"suppressed_by_vex": True, "status": "open"}) == "suppressed"
    assert model._status({"waived": True, "status": "open"}) == "accepted"
    assert (
        model._status_label({"waiver_status": "review_due", "waiver_owner": "security"})
        == "Waiver review due owner=security"
    )
    assert model._status_label({"under_investigation": True}) == "Under investigation"
    assert model._vex_status({"under_investigation": True}) == "under_investigation"
    assert model._vex_status({"suppressed_by_vex": True}) == "suppressed"

    dossier = model._finding_dossier_model(
        {
            "cve_id": "CVE-2026-0006",
            "priority_label": "Critical",
            "provider_evidence": {
                "nvd": {"references": ["https://nvd.example/ref"]},
                "epss": {"date": "2026-05-01"},
                "kev": {"due_date": "2026-06-01", "required_action": "Apply update."},
            },
        }
    )
    assert {"label": "NVD references", "value": "1"} in dossier["provider"]
    assert {"label": "Score date", "value": "2026-05-01"} in dossier["provider"]
    assert {"label": "KEV due date", "value": "2026-06-01"} in dossier["provider"]


def test_executive_model_artifact_bundle_and_workspace_nav_branches() -> None:
    bundle = model._bundle_contents_model([{"label": "summary.md", "detail": "Markdown report"}])
    artifacts = model._artifact_model(
        reports=[
            SimpleNamespace(id=None, kind="summary", format="markdown", sha256="ignored"),
            SimpleNamespace(
                id="report-1",
                kind="executive",
                format="html",
                sha256="1234567890abcdef",
            ),
        ],
        bundles=[
            SimpleNamespace(id=None, sha256="ignored"),
            SimpleNamespace(id="bundle-1", sha256="abcdef1234567890"),
        ],
    )
    nav_without_run = model._workspace_nav("project-1", None, "Payments")
    nav_with_run = model._workspace_nav("project-1", "run-1", "Payments")

    assert bundle == {
        "generated": True,
        "items": [{"name": "summary.md", "detail": "Markdown report", "size": "downloadable"}],
    }
    assert [item["label"] for item in artifacts] == [
        "executive (html)",
        "Evidence ZIP",
        "Verify evidence bundle",
    ]
    assert artifacts[0]["url"] == "/api/reports/report-1/download"
    assert artifacts[1]["url"] == "/api/evidence-bundles/bundle-1/download"
    assert model._workspace_nav(None, "run-1", "Payments") is None
    assert nav_without_run is not None
    assert [group["label"] for group in nav_without_run["groups"]] == [
        "Analyze",
        "Context",
        "Operate",
    ]
    assert nav_with_run is not None
    assert [group["label"] for group in nav_with_run["groups"]] == [
        "Analyze",
        "Context",
        "Run",
        "Operate",
    ]
    assert nav_with_run["groups"][2]["links"][1]["active"] is True
