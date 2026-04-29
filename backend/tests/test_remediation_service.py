from __future__ import annotations

from vuln_prioritizer.models import FindingProvenance, InputOccurrence, KevData
from vuln_prioritizer.services.remediation import (
    RemediationService,
    derive_remediation,
    render_recommended_action,
)


def _occurrence(
    *,
    component_name: str | None = None,
    component_version: str | None = None,
    purl: str | None = None,
    package_type: str | None = None,
    dependency_path: str | None = None,
    file_path: str | None = None,
    fix_versions: list[str] | None = None,
    vex_status: str | None = None,
    target_kind: str = "generic",
    target_ref: str | None = None,
    asset_id: str | None = None,
    asset_owner: str | None = None,
    asset_business_service: str | None = None,
) -> InputOccurrence:
    return InputOccurrence(
        cve_id="CVE-2024-0001",
        component_name=component_name,
        component_version=component_version,
        purl=purl,
        package_type=package_type,
        dependency_path=dependency_path,
        file_path=file_path,
        fix_versions=list(fix_versions or []),
        vex_status=vex_status,
        target_kind=target_kind,
        target_ref=target_ref,
        asset_id=asset_id,
        asset_owner=asset_owner,
        asset_business_service=asset_business_service,
    )


def test_remediation_service_prefers_actionable_component_evidence() -> None:
    remediation = RemediationService().derive(
        [
            _occurrence(
                component_name="widget",
                component_version="1.2.3",
                purl="pkg:npm/acme/widget@1.2.3",
                package_type="npm",
                dependency_path="package-lock.json",
                fix_versions=["2.0.0", "1.10.0"],
            ),
            _occurrence(
                component_name="widget",
                component_version="1.2.3",
                purl="pkg:npm/acme/widget@1.2.3",
                package_type="npm",
                dependency_path="package-lock.json",
                fix_versions=["1.2.0"],
            ),
        ]
    )

    assert remediation.strategy == "upgrade"
    assert remediation.ecosystem == "npm"
    assert [component.model_dump() for component in remediation.components] == [
        {
            "name": "widget",
            "current_version": "1.2.3",
            "fixed_versions": ["1.2.0", "1.10.0", "2.0.0"],
            "package_type": "npm",
            "purl": "pkg:npm/acme/widget@1.2.3",
            "path": "package-lock.json",
            "occurrence_count": 2,
            "targets": [],
            "asset_ids": [],
            "services": [],
            "owners": [],
        }
    ]

    action = render_recommended_action(remediation, priority_label="High")
    assert "Upgrade affected components with known fixes in npm" in action
    assert "widget 1.2.3 (package-lock.json) -> 1.2.0, 1.10.0, 2.0.0" in action


def test_remediation_service_reviews_known_ecosystem_without_fix_versions() -> None:
    provenance = FindingProvenance(
        occurrences=[
            _occurrence(
                component_name="django",
                component_version="4.2.0",
                package_type="python",
                dependency_path="requirements.txt",
            )
        ]
    )

    remediation = derive_remediation(provenance)

    assert remediation.strategy == "review-upgrade-options"
    assert remediation.ecosystem == "pypi"
    assert [component.model_dump() for component in remediation.components] == [
        {
            "name": "django",
            "current_version": "4.2.0",
            "fixed_versions": [],
            "package_type": "python",
            "purl": None,
            "path": "requirements.txt",
            "occurrence_count": 1,
            "targets": [],
            "asset_ids": [],
            "services": [],
            "owners": [],
        }
    ]

    action = render_recommended_action(remediation, priority_label="Medium")
    assert "Review available upgrade options in pypi" in action
    assert "django 4.2.0 (requirements.txt)" in action


def test_remediation_service_preserves_generic_fix_only_evidence() -> None:
    remediation = RemediationService().derive(
        [
            _occurrence(fix_versions=["2.0.0", "1.0.0"]),
            _occurrence(fix_versions=["1.5.0"]),
        ]
    )

    assert remediation.strategy == "upgrade"
    assert remediation.ecosystem is None
    assert [component.model_dump() for component in remediation.components] == [
        {
            "name": None,
            "current_version": None,
            "fixed_versions": ["1.0.0", "1.5.0", "2.0.0"],
            "package_type": None,
            "purl": None,
            "path": None,
            "occurrence_count": 2,
            "targets": [],
            "asset_ids": [],
            "services": [],
            "owners": [],
        }
    ]


def test_remediation_components_include_occurrence_routing_context_and_purl_name() -> None:
    remediation = RemediationService().derive(
        [
            _occurrence(
                purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                fix_versions=["2.17.1"],
                target_kind="repository",
                target_ref="backend/pom.xml",
                asset_id="asset-api",
                asset_owner="team-app",
                asset_business_service="identity",
            ),
            _occurrence(
                purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                fix_versions=["2.17.0"],
                target_kind="repository",
                target_ref="worker/pom.xml",
                asset_id="asset-worker",
                asset_owner="team-platform",
                asset_business_service="identity",
            ),
        ]
    )

    component = remediation.components[0]
    assert component.name == "log4j-core"
    assert component.occurrence_count == 2
    assert component.fixed_versions == ["2.17.0", "2.17.1"]
    assert component.targets == ["repository:backend/pom.xml", "repository:worker/pom.xml"]
    assert component.asset_ids == ["asset-api", "asset-worker"]
    assert component.services == ["identity"]
    assert component.owners == ["team-app", "team-platform"]


def test_remediation_service_falls_back_to_priority_only_without_component_evidence() -> None:
    remediation = RemediationService().derive([])

    assert remediation.strategy == "generic-priority-guidance"
    assert remediation.ecosystem is None
    assert remediation.components == []
    assert (
        render_recommended_action(remediation, priority_label="Low")
        == "Document the finding, monitor for changes in exploitability or exposure, and address "
        "it during the normal patch cycle."
    )


def test_remediation_uses_active_occurrences_and_surfaces_kev_action() -> None:
    remediation = RemediationService().derive(
        [
            _occurrence(
                component_name="active-lib",
                component_version="1.0.0",
                package_type="npm",
                dependency_path="package-lock.json",
            ),
            _occurrence(
                component_name="suppressed-lib",
                component_version="1.0.0",
                package_type="npm",
                fix_versions=["2.0.0"],
                vex_status="fixed",
            ),
        ],
        kev=KevData(
            cve_id="CVE-2024-0001",
            in_kev=True,
            required_action="Apply vendor update.",
            due_date="2026-05-01",
        ),
    )

    assert remediation.strategy == "review-upgrade-options"
    assert remediation.evidence_level == "kev_action"
    assert remediation.suppressed_occurrence_count == 1
    assert remediation.kev_required_action == "Apply vendor update."
    assert remediation.kev_due_date == "2026-05-01"
    assert [component.name for component in remediation.components] == ["active-lib"]
    action = render_recommended_action(remediation, priority_label="Critical")
    assert action.startswith("CISA KEV required action: Apply vendor update.")
    assert "KEV due date: 2026-05-01." in action
