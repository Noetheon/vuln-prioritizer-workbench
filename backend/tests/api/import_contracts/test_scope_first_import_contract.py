from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from utils.import_contracts import (
    completed_run_payload,
    completed_run_summary,
    configure_upload_dir,
)
from utils.workbench_env import (
    create_project_via_api,
    create_workbench_api_env,
    local_api_headers,
)

_PRODUCTION_ASSET = "asset-prod-critical"
_DEVELOPMENT_ASSET = "asset-dev-low"
_FIXED_VERSION = "2.17.1"


@pytest.fixture(scope="module")
def scope_first_import_contract(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, Any]]:
    """Run one real queued import and expose its evidence-backed public projections."""
    workbench_api_env, cleanup = create_workbench_api_env()
    try:
        configure_upload_dir(
            workbench_api_env,
            tmp_path_factory.mktemp("scope-first-import"),
        )
        headers = local_api_headers(workbench_api_env.client)
        project = create_project_via_api(workbench_api_env.client, headers)
        occurrence_csv = "\n".join(
            [
                (
                    "cve_id,target_ref,component_name,component_version,purl,"
                    "fix_versions,raw_severity"
                ),
                (
                    "CVE-2021-44228,prod-app,log4j-core,2.14.1,"
                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1,"
                    f"{_FIXED_VERSION},CRITICAL"
                ),
                (
                    "CVE-2021-44228,dev-tool,log4j-api,2.13.0,"
                    "pkg:maven/org.apache.logging.log4j/log4j-api@2.13.0,,CRITICAL"
                ),
                "",
            ]
        ).encode()
        asset_context_csv = "\n".join(
            [
                (
                    "target_kind,target_ref,asset_id,owner,business_service,"
                    "criticality,exposure,environment"
                ),
                (
                    f"generic,prod-app,{_PRODUCTION_ASSET},team-payments,payments,"
                    "critical,public,prod"
                ),
                (
                    f"generic,dev-tool,{_DEVELOPMENT_ASSET},team-developer-experience,"
                    "developer-tools,low,internal,dev"
                ),
                "",
            ]
        ).encode()
        vex = json.dumps(
            {
                "statements": [
                    {
                        "action_statement": "Investigation is limited to the production component.",
                        "justification": "component_not_present",
                        "products": [
                            {
                                "identifiers": {
                                    "purl": ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
                                }
                            }
                        ],
                        "status": "under_investigation",
                        "vulnerability": {"name": "CVE-2021-44228"},
                    }
                ]
            },
            sort_keys=True,
        ).encode()

        response = workbench_api_env.client.post(
            f"/api/v1/projects/{project['id']}/imports",
            headers=headers,
            data={"input_type": "generic-occurrence-csv"},
            files={
                "file": ("scope-first.csv", occurrence_csv, "text/csv"),
                "asset_context_file": (
                    "scope-first-assets.csv",
                    asset_context_csv,
                    "text/csv",
                ),
                "vex_file": ("scope-first-vex.json", vex, "application/json"),
            },
        )

        assert response.status_code == 200, response.text
        assert response.json()["workflow"]["status"] == "pending"
        run = completed_run_payload(workbench_api_env, response, headers=headers)
        summary = completed_run_summary(workbench_api_env, run["id"], headers=headers)
        assert run["status"] == "succeeded", {
            "diagnostics": run.get("diagnostics"),
            "status": run.get("status"),
            "workflow": run.get("workflow"),
        }
        assert run["workflow"]["status"] == "succeeded"
        assert run["evidence"]["schema_version"] == "analysis-evidence.v2"
        assert run["evidence"]["analysis_evidence_id"]
        assert run["asset_context"]["matched_occurrences"] == 2
        assert run["vex"]["matched_occurrences"] == 1

        findings_response = workbench_api_env.client.get(
            f"/api/v1/projects/{project['id']}/findings/",
            headers=headers,
            params={"sort": "operational", "direction": "asc"},
        )
        assert findings_response.status_code == 200, findings_response.text
        assert findings_response.json()["count"] == 2
        ordered_findings = findings_response.json()["data"]
        findings = {finding["asset_key"]: finding for finding in ordered_findings}
        assert set(findings) == {_PRODUCTION_ASSET, _DEVELOPMENT_ASSET}
        assert all(
            finding["evidence"]["schema_version"] == "finding-decision-evidence.v2"
            and finding["evidence"]["analysis_run_id"] == run["id"]
            and finding["evidence"]["project_id"] == project["id"]
            for finding in ordered_findings
        )

        details: dict[str, dict[str, Any]] = {}
        for asset_key, finding in findings.items():
            detail_response = workbench_api_env.client.get(
                f"/api/v1/findings/{finding['id']}",
                headers=headers,
            )
            assert detail_response.status_code == 200, detail_response.text
            details[asset_key] = detail_response.json()

        yield {
            "details": details,
            "findings": findings,
            "ordered_findings": ordered_findings,
            "run": run,
            "summary": summary,
        }
    finally:
        cleanup()


def test_scope_first_sidecar_context_is_persisted_per_finding(
    scope_first_import_contract: dict[str, Any],
) -> None:
    findings = scope_first_import_contract["findings"]
    production = findings[_PRODUCTION_ASSET]
    development = findings[_DEVELOPMENT_ASSET]

    assert production["asset_criticality"] == "critical"
    assert production["exposure"] == "internet-facing"
    assert production["asset_environment"] == "production"
    assert development["asset_criticality"] == "low"
    assert development["exposure"] == "internal"
    assert development["asset_environment"] == "development"

    production_scope = production["evidence"]["occurrence_scope"]
    assert production_scope["target_ref"] == "prod-app"
    assert production_scope["asset_id"] == _PRODUCTION_ASSET
    assert production_scope["asset_owner"] == "team-payments"
    assert production_scope["asset_business_service"] == "payments"
    assert production_scope["asset_criticality"] == "critical"
    assert production_scope["asset_exposure"] == "internet-facing"
    assert production_scope["asset_environment"] == "production"

    development_scope = development["evidence"]["occurrence_scope"]
    assert development_scope["target_ref"] == "dev-tool"
    assert development_scope["asset_id"] == _DEVELOPMENT_ASSET
    assert development_scope["asset_owner"] == "team-developer-experience"
    assert development_scope["asset_business_service"] == "developer-tools"
    assert development_scope["asset_criticality"] == "low"
    assert development_scope["asset_exposure"] == "internal"
    assert development_scope["asset_environment"] == "development"


def test_scope_first_sidecar_context_drives_distinct_scores(
    scope_first_import_contract: dict[str, Any],
) -> None:
    findings = scope_first_import_contract["findings"]
    production = findings[_PRODUCTION_ASSET]
    development = findings[_DEVELOPMENT_ASSET]
    production_reasons = production["evidence"]["priority_evidence"]["operational_score_reasons"]
    development_reasons = development["evidence"]["priority_evidence"]["operational_score_reasons"]

    assert production["risk_score"] > development["risk_score"]
    assert production["risk_score"] - development["risk_score"] == 19.0
    assert (
        production["evidence"]["priority_evidence"]["operational_score"] == production["risk_score"]
    )
    assert (
        development["evidence"]["priority_evidence"]["operational_score"]
        == development["risk_score"]
    )
    assert "internet-facing asset context: +8" in production_reasons
    assert "production asset context: +4" in production_reasons
    assert "critical asset criticality: +7" in production_reasons
    assert "internet-facing asset context: +8" not in development_reasons
    assert "production asset context: +4" not in development_reasons
    assert "critical asset criticality: +7" not in development_reasons


def test_scope_first_findings_receive_unique_operational_ranks(
    scope_first_import_contract: dict[str, Any],
) -> None:
    findings = scope_first_import_contract["findings"]
    production = findings[_PRODUCTION_ASSET]
    development = findings[_DEVELOPMENT_ASSET]

    assert production["priority_rank"] == development["priority_rank"]
    assert production["operational_rank"] == 1
    assert development["operational_rank"] == 2
    assert len({production["operational_rank"], development["operational_rank"]}) == 2
    production_statement = production["evidence"]["priority_evidence"]["raw"]["decision_guidance"][
        "decision_statement"
    ]
    development_statement = development["evidence"]["priority_evidence"]["raw"][
        "decision_guidance"
    ]["decision_statement"]
    assert production_statement.startswith("Top finding #1:")
    assert development_statement.startswith("Top finding #2:")


def test_separate_imports_converge_to_one_project_wide_operational_queue(
    tmp_path: Any,
) -> None:
    workbench_api_env, cleanup = create_workbench_api_env()
    try:
        configure_upload_dir(workbench_api_env, tmp_path)
        headers = local_api_headers(workbench_api_env.client)
        project = create_project_via_api(workbench_api_env.client, headers)
        for cve_id in ("CVE-2024-3094", "CVE-2021-44228"):
            response = workbench_api_env.client.post(
                f"/api/v1/projects/{project['id']}/imports",
                headers=headers,
                data={"input_type": "cve-list"},
                files={"file": ("findings.txt", f"{cve_id}\n".encode(), "text/plain")},
            )
            assert response.status_code == 200, response.text
            completed = completed_run_payload(workbench_api_env, response, headers=headers)
            assert completed["status"] == "succeeded"

        findings_response = workbench_api_env.client.get(
            f"/api/v1/projects/{project['id']}/findings/",
            headers=headers,
            params={"sort": "operational", "direction": "asc"},
        )
        assert findings_response.status_code == 200, findings_response.text
        findings = findings_response.json()["data"]
        assert len(findings) == 2
        assert [finding["operational_rank"] for finding in findings] == [1, 2]
        assert findings[0]["risk_score"] > findings[1]["risk_score"]
        for expected_rank, finding in enumerate(findings, start=1):
            statement = finding["evidence"]["priority_evidence"]["raw"]["decision_guidance"][
                "decision_statement"
            ]
            assert statement.startswith(f"Top finding #{expected_rank}:")
    finally:
        cleanup()


def test_shared_component_label_cannot_drift_across_projects(
    tmp_path: Any,
) -> None:
    workbench_api_env, cleanup = create_workbench_api_env()
    try:
        configure_upload_dir(workbench_api_env, tmp_path)
        headers = local_api_headers(workbench_api_env.client)
        first_project = create_project_via_api(
            workbench_api_env.client,
            headers,
            name="Immutable component evidence",
        )
        second_project = create_project_via_api(
            workbench_api_env.client,
            headers,
            name="Shared component mutation",
        )

        def import_component(project_id: str, component_name: str) -> None:
            payload = "\n".join(
                [
                    "cve_id,target_ref,component_name,component_version,purl,source",
                    (f"CVE-2021-44228,repo-a,{component_name},,pkg:pypi/django@3.0.0,test"),
                    "",
                ]
            ).encode()
            response = workbench_api_env.client.post(
                f"/api/v1/projects/{project_id}/imports",
                headers=headers,
                data={"input_type": "generic-occurrence-csv"},
                files={"file": ("component.csv", payload, "text/csv")},
            )
            assert response.status_code == 200, response.text
            completed = completed_run_payload(
                workbench_api_env,
                response,
                headers=headers,
            )
            assert completed["status"] == "succeeded"

        def first_finding() -> dict[str, Any]:
            response = workbench_api_env.client.get(
                f"/api/v1/projects/{first_project['id']}/findings/",
                headers=headers,
            )
            assert response.status_code == 200, response.text
            assert response.json()["count"] == 1
            return response.json()["data"][0]

        import_component(first_project["id"], "")
        before = first_finding()
        assert before["evidence"]["occurrence_scope"]["component_name"] is None
        assert before["component_name"] == "django"
        assert before["component_version"] == "3.0.0"

        import_component(second_project["id"], "EVIL-LABEL")
        after = first_finding()

        assert {
            key: after[key] for key in ("component_name", "component_version", "component_purl")
        } == {key: before[key] for key in ("component_name", "component_version", "component_purl")}
        assert "EVIL-LABEL" not in json.dumps(after, sort_keys=True)

        preview = workbench_api_env.client.post(
            f"/api/v1/projects/{first_project['id']}/github/issues/preview",
            headers=headers,
            json={"finding_ids": [after["id"]]},
        )
        assert preview.status_code == 200, preview.text
        issue = preview.json()["data"][0]
        assert "django 3.0.0" in issue["body"]
        assert "EVIL-LABEL" not in issue["body"]
    finally:
        cleanup()


@pytest.fixture(scope="module")
def shared_component_query_contract(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, Any]]:
    """Capture finding-query behavior before and after a foreign component import."""
    workbench_api_env, cleanup = create_workbench_api_env()
    try:
        configure_upload_dir(
            workbench_api_env,
            tmp_path_factory.mktemp("shared-component-query"),
        )
        headers = local_api_headers(workbench_api_env.client)
        first_project = create_project_via_api(
            workbench_api_env.client,
            headers,
            name="Component query isolation",
        )
        second_project = create_project_via_api(
            workbench_api_env.client,
            headers,
            name="Foreign component metadata",
        )

        def import_rows(project_id: str, rows: list[str]) -> None:
            payload = "\n".join(
                [
                    "cve_id,target_ref,component_name,component_version,purl,source",
                    *rows,
                    "",
                ]
            ).encode()
            response = workbench_api_env.client.post(
                f"/api/v1/projects/{project_id}/imports",
                headers=headers,
                data={"input_type": "generic-occurrence-csv"},
                files={"file": ("components.csv", payload, "text/csv")},
            )
            assert response.status_code == 200, response.text
            completed = completed_run_payload(
                workbench_api_env,
                response,
                headers=headers,
            )
            assert completed["status"] == "succeeded"

        def snapshot(**params: Any) -> dict[str, Any]:
            response = workbench_api_env.client.get(
                f"/api/v1/projects/{first_project['id']}/findings/",
                headers=headers,
                params=params,
            )
            assert response.status_code == 200, response.text
            payload = response.json()
            return {
                "count": payload["count"],
                "rows": [(item["cve_id"], item["component_name"]) for item in payload["data"]],
            }

        import_rows(
            first_project["id"],
            [
                ("CVE-2021-44228,repo-a,A-LOCAL,,pkg:pypi/django@3.0.0,test"),
                ("CVE-2021-45046,repo-b,M-LOCAL,,pkg:pypi/flask@2.0.0,test"),
            ],
        )
        query_params = {
            "sort": "component",
            "direction": "asc",
        }
        before = {
            "local_search": snapshot(q="A-LOCAL"),
            "foreign_search": snapshot(q="Z-MUTATED"),
            "sorted": snapshot(**query_params),
            "first_page": snapshot(**query_params, limit=1, offset=0),
            "second_page": snapshot(**query_params, limit=1, offset=1),
        }

        import_rows(
            second_project["id"],
            [("CVE-2021-44228,repo-x,Z-MUTATED,,pkg:pypi/django@3.0.0,test")],
        )
        after = {
            "local_search": snapshot(q="A-LOCAL"),
            "foreign_search": snapshot(q="Z-MUTATED"),
            "sorted": snapshot(**query_params),
            "first_page": snapshot(**query_params, limit=1, offset=0),
            "second_page": snapshot(**query_params, limit=1, offset=1),
        }
        yield {"before": before, "after": after}
    finally:
        cleanup()


def test_shared_component_metadata_cannot_leak_into_project_search(
    shared_component_query_contract: dict[str, Any],
) -> None:
    before = shared_component_query_contract["before"]
    after = shared_component_query_contract["after"]

    assert (
        before["local_search"]
        == after["local_search"]
        == {
            "count": 1,
            "rows": [("CVE-2021-44228", "A-LOCAL")],
        }
    )
    assert (
        before["foreign_search"]
        == after["foreign_search"]
        == {
            "count": 0,
            "rows": [],
        }
    )


def test_shared_component_metadata_cannot_change_project_component_sort(
    shared_component_query_contract: dict[str, Any],
) -> None:
    expected = {
        "count": 2,
        "rows": [
            ("CVE-2021-44228", "A-LOCAL"),
            ("CVE-2021-45046", "M-LOCAL"),
        ],
    }
    assert shared_component_query_contract["before"]["sorted"] == expected
    assert shared_component_query_contract["after"]["sorted"] == expected


def test_shared_component_metadata_cannot_change_project_pagination(
    shared_component_query_contract: dict[str, Any],
) -> None:
    before = shared_component_query_contract["before"]
    after = shared_component_query_contract["after"]
    expected_first_page = {
        "count": 2,
        "rows": [("CVE-2021-44228", "A-LOCAL")],
    }
    expected_second_page = {
        "count": 2,
        "rows": [("CVE-2021-45046", "M-LOCAL")],
    }

    assert before["first_page"] == after["first_page"] == expected_first_page
    assert before["second_page"] == after["second_page"] == expected_second_page


def test_scope_first_under_investigation_does_not_leak_to_unmatched_component(
    scope_first_import_contract: dict[str, Any],
) -> None:
    findings = scope_first_import_contract["findings"]
    details = scope_first_import_contract["details"]
    production = findings[_PRODUCTION_ASSET]
    development = findings[_DEVELOPMENT_ASSET]

    assert details[_PRODUCTION_ASSET]["occurrences"][0]["vex_status"] == ("under_investigation")
    assert details[_DEVELOPMENT_ASSET]["occurrences"][0]["vex_status"] is None
    assert production["evidence"]["occurrence_scope"]["vex_status"] == ("under_investigation")
    assert development["evidence"]["occurrence_scope"]["vex_status"] is None
    assert production["under_investigation"] is True
    assert production["evidence"]["governance"]["under_investigation"] is True
    assert production["evidence"]["governance"]["vex_statuses"] == {"under_investigation": 1}
    assert development["under_investigation"] is False
    assert development["evidence"]["governance"]["under_investigation"] is False
    assert development["evidence"]["governance"]["vex_statuses"] == {}


def test_scope_first_remediation_does_not_leak_fixed_version_to_other_component(
    scope_first_import_contract: dict[str, Any],
) -> None:
    findings = scope_first_import_contract["findings"]
    details = scope_first_import_contract["details"]
    production = findings[_PRODUCTION_ASSET]
    development = findings[_DEVELOPMENT_ASSET]
    production_action = production["evidence"]["remediation"]["recommended_action"]
    development_action = development["evidence"]["remediation"]["recommended_action"]

    assert details[_PRODUCTION_ASSET]["occurrences"][0]["fix_versions"] == [_FIXED_VERSION]
    assert details[_DEVELOPMENT_ASSET]["occurrences"][0]["fix_versions"] in (None, [])
    assert production_action == production["recommended_action"]
    assert development_action == development["recommended_action"]
    assert "log4j-core 2.14.1" in production_action
    assert _FIXED_VERSION in production_action
    assert "log4j-api 2.13.0" in development_action
    assert "no fixed version was captured" in development_action
    assert "log4j-core 2.14.1" not in development_action
    assert _FIXED_VERSION not in development_action


def test_scope_first_run_counts_account_for_each_projected_finding(
    scope_first_import_contract: dict[str, Any],
) -> None:
    for payload in (
        scope_first_import_contract["run"],
        scope_first_import_contract["summary"],
    ):
        counts = payload["evidence"]["counts"]
        assert counts["finding_count"] == 2
        assert counts["created_findings"] + counts["updated_findings"] == counts["finding_count"]
        assert sum(counts["counts_by_priority"].values()) == counts["finding_count"]
        assert counts["under_investigation_count"] == 1


def test_scope_first_run_exposes_replay_and_observation_identities(
    scope_first_import_contract: dict[str, Any],
) -> None:
    run = scope_first_import_contract["run"]
    findings = scope_first_import_contract["findings"]
    semantics = run["evidence"]["analysis_semantics"]

    assert semantics["decision_graph_schema_version"] == "scope-first-decision-graph.v2"
    assert semantics["finding_dedup_key_version"] == "finding-scope-v2"
    for key in (
        "normalized_input_sha256",
        "policy_sha256",
        "shared_facts_sha256",
        "replay_sha256",
    ):
        assert len(semantics[key]) == 64
        int(semantics[key], 16)

    observation_keys = {
        finding["evidence"]["occurrences"][0]["dedup"]["observation_key"]
        for finding in findings.values()
    }
    assert len(observation_keys) == 2
    assert all(key.startswith("vpw-observation-v1:") for key in observation_keys)
    assert all(
        finding["evidence"]["occurrences"][0]["dedup"]["observation_key_version"]
        == "observation-v1"
        for finding in findings.values()
    )
