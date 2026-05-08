from __future__ import annotations

from vuln_prioritizer import reporting_executive_sections as sections


def test_executive_section_empty_state_helpers_render_stable_copy() -> None:
    assert sections._severity_signal_chart([]) == '<p class="er-empty">not supplied</p>'
    assert sections._provider_cards_html([]) == '<p class="er-empty">not supplied</p>'
    assert sections._priority_interpretation_html([]) == '<p class="er-empty">not supplied</p>'
    assert sections._next_steps_html([]) == '<p class="er-empty">not supplied</p>'
    assert sections._coverage_average([]) == "not available"
    assert (
        sections._waterfall_html({"projected_risk_reduction": "modelled"})
        == '<p class="er-empty">not supplied</p>'
    )
    assert sections._provider_freshness_table([]) == '<p class="er-empty">not supplied</p>'
    assert sections._quality_matrix_html([]) == '<p class="er-empty">not supplied</p>'
    assert sections._mapping_confidence_html({"rows": []}) == '<p class="er-empty">not supplied</p>'
    assert sections._evidence_contents_html({"items": []}) == '<p class="er-empty">not supplied</p>'
    assert sections._missing_context_html([]) == '<p class="er-empty">not supplied</p>'
    assert sections._scatter_svg([]) == '<p class="er-empty">not supplied</p>'
    assert sections._quadrant_scatter_svg([]) == '<p class="er-empty">not supplied</p>'


def test_detection_coverage_renders_weak_items_and_defaults() -> None:
    html = sections._detection_coverage_html(
        {
            "summary": {"partial": 1, "not_covered": 2, "unknown": 3},
            "total": 6,
            "weak_items": [
                {
                    "technique_id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "coverage_level": "partial",
                    "finding_count": 4,
                    "owner": "detection-team",
                    "recommended_action": "Tune detection rules.",
                },
                {"technique_id": "T1190"},
            ],
            "note": "Review coverage weekly.",
        }
    )

    assert "T1059" in html
    assert "Command and Scripting Interpreter" in html
    assert "detection-team" in html
    assert "Review coverage." in html
    assert "Review coverage weekly." in html


def test_workspace_navigation_helpers_render_interactive_sidebar_and_icons() -> None:
    assert sections._workspace_nav_html(None) == ""
    assert sections._workspace_nav_html({"groups": "invalid"}) == ""
    assert sections._workspace_nav_html({"groups": [{"label": "Bad", "links": "invalid"}]}) == ""

    html = sections._workspace_nav_html(
        {
            "project": "Project <Alpha>",
            "groups": [
                "skip-me",
                {
                    "label": "Main",
                    "links": [
                        "skip-me",
                        {"label": "Findings", "href": "/findings", "active": True},
                        {"label": "Settings"},
                    ],
                },
            ],
        },
        interactive=True,
    )

    assert "sidebar-toggle" in html
    assert "Project &lt;Alpha&gt;" in html
    assert 'aria-current="page"' in html
    assert 'href="#' in html
    assert "Collapse" in html
    assert "Vuln Prioritizer Workbench" in sections._workspace_app_header_html()

    labels = [
        "Dashboard",
        "Import",
        "Findings",
        "Intelligence",
        "Governance",
        "Assets",
        "Waivers",
        "Coverage",
        "Run Artifacts",
        "Executive Report",
        "Settings",
        "Unknown",
    ]
    for label in labels:
        assert "<svg" in sections._workspace_nav_icon(label)


def test_executive_presentational_helpers_render_quality_and_evidence_branches() -> None:
    assert "Critical" in sections._decision_item(
        {
            "tone": "critical",
            "priority": "Critical",
            "cve": "CVE-2026-0001",
            "action": "Patch immediately.",
        }
    )
    assert "Open" in sections._bar_row({"label": "Open", "tone": "critical", "pct": 75, "count": 3})
    assert "not supplied" in sections._rollup_panel("Empty", [])
    assert "Payments" in sections._rollup_panel(
        "By service",
        [{"label": "Payments", "pct": 100, "count": 2}],
    )
    assert 'max="100"' in sections._status_segment("Open", 2, 0, "critical")
    assert "report.html" in sections._artifact_row(
        {"url": "/reports/report.html", "label": "HTML", "detail": "Ready"}
    )
    assert "No provider or input warnings" in sections._quality_notes_html([])
    assert "Provider delayed" in sections._quality_notes_html(["Provider delayed"])

    confidence_html = sections._mapping_confidence_html(
        {
            "available": True,
            "total": 2,
            "rows": [{"label": "Reviewed", "count": 2, "pct": 100}],
        }
    )
    assert "Reviewed" in confidence_html
    assert "100%" in confidence_html

    unavailable_html = sections._mapping_confidence_html(
        {"available": False, "rows": [{"detail": "Mapping source not supplied."}]}
    )
    assert "Mapping source not supplied." in unavailable_html

    evidence_html = sections._evidence_contents_html(
        {
            "generated": False,
            "items": [
                {
                    "name": "manifest.json",
                    "size": "1 KB",
                    "detail": "Evidence manifest",
                }
            ],
        }
    )
    assert "Bundle has not been generated" in evidence_html
    assert "manifest.json" in evidence_html

    missing_html = sections._missing_context_html(
        [
            {
                "label": "Asset owners",
                "detail": "Missing owner context",
                "value": 3,
                "pct": 30,
                "tone": "medium",
            }
        ]
    )
    assert "Asset owners" in missing_html
    assert "Missing owner context" in missing_html


def test_scatter_helpers_render_accessible_points_and_kev_state() -> None:
    points = [
        {
            "tone": "critical",
            "kev": True,
            "x": 300.0,
            "y": 50.0,
            "cve": "CVE-2026-0002",
            "cvss": 9.8,
            "epss": 0.91,
        },
        {
            "tone": "low",
            "kev": False,
            "x": 80.0,
            "y": 190.0,
            "cve": "CVE-2026-0003",
            "cvss": None,
            "epss": None,
        },
    ]

    scatter = sections._scatter_svg(points)
    quadrant = sections._quadrant_scatter_svg(points)

    assert "CVE-2026-0002: CVSS 9.8, EPSS 0.910, KEV-listed" in scatter
    assert "CVE-2026-0003: CVSS N.A., EPSS N.A., not KEV-listed" in scatter
    assert 'stroke="#dc2626"' in quadrant
    assert "High EPSS / High CVSS" in quadrant
