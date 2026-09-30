from __future__ import annotations

import copy
import json
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from scripts import check_quality_health as health
from scripts import check_quality_policy as policy
from scripts import quality_gate as gate
from scripts import quality_trends as trends

BINDING = {"repository": "owner/repo", "sha": "a" * 40, "run_id": "17", "attempt": "1"}
SELECTED = dict.fromkeys(gate.GATES, True)
NEEDS = {name: {"result": "success"} for name in ("selection", "policy", "contracts")}


def receipts():
    return [
        {
            "schema": gate.SCHEMA,
            "context": dict(BINDING),
            "gate": name,
            "selected": True,
            "status": "passed",
            "metrics": {"tests": 3},
        }
        for name in gate.GATES
    ]


def test_complete_receipts_are_bound_to_the_current_commit():
    result = gate.verify(receipts(), SELECTED, NEEDS, BINDING)
    assert set(result["contracts"]) == set(gate.GATES)
    assert result["context"] == BINDING


@pytest.mark.parametrize(
    "damage", ["missing", "duplicate", "old_sha", "old_attempt", "failed", "skipped", "empty"]
)
def test_admission_rejects_incomplete_or_stale_evidence(damage):
    values = receipts()
    if damage == "missing":
        values.pop()
    elif damage == "duplicate":
        values.append(copy.deepcopy(values[0]))
    elif damage == "old_sha":
        values[0]["context"]["sha"] = "b" * 40
    elif damage == "old_attempt":
        values[0]["context"]["attempt"] = "0"
    elif damage == "empty":
        values[0]["metrics"] = {}
    else:
        values[0]["status"] = damage
    with pytest.raises(ValueError):
        gate.verify(values, SELECTED, NEEDS, BINDING)


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "neutral"])
def test_failed_upstream_job_cannot_turn_into_green_admission(result):
    needs = copy.deepcopy(NEEDS)
    needs["selection"]["result"] = result
    with pytest.raises(ValueError):
        gate.verify(receipts(), SELECTED, needs, BINDING)


def test_unneeded_gate_requires_explicit_matching_skip_receipt():
    selected = {**SELECTED, "grype": False}
    values = receipts()
    values[-1].update(selected=False, status="not_required", metrics={})
    assert gate.verify(values, selected, NEEDS, BINDING)
    values[-1]["selected"] = True
    with pytest.raises(ValueError):
        gate.verify(values, selected, NEEDS, BINDING)


@pytest.mark.parametrize(
    "value", ["{}", "null", "[]", '{"core": true}', json.dumps(dict.fromkeys(gate.GATES, 1))]
)
def test_incomplete_or_truthy_selection_is_rejected(value):
    with pytest.raises(ValueError):
        gate.selection(value)


@pytest.mark.parametrize("child", ["", "<skipped/>", "<failure/>", "<error/>"])
def test_junit_requires_executed_successful_cases(tmp_path, child):
    path = tmp_path / "junit.xml"
    path.write_text(
        "<testsuites/>" if not child else f"<testsuite><testcase>{child}</testcase></testsuite>"
    )
    with pytest.raises(ValueError):
        gate.junit(path)


def test_successful_noop_command_cannot_reuse_stale_junit(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "context", lambda: dict(BINDING))
    path = tmp_path / "build/recovery.xml"
    path.parent.mkdir()
    path.write_text("<testsuite><testcase/></testsuite>")
    monkeypatch.setattr(gate, "execute", lambda *a, **kw: None)
    assert gate.run_gate(tmp_path, "recovery", SELECTED, "pull_request") == 1
    report = json.loads((tmp_path / "build/quality-receipts/recovery.json").read_text())
    assert report["status"] == "failed"
    assert not path.exists()


def test_scheduled_property_seed_is_recorded_and_replayable(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "context", lambda: dict(BINDING))
    executions = []

    def execute(command, *, cwd, env, **kwargs):
        executions.append(env["PYTEST_ADDOPTS"])
        path = cwd / "build/property-extended.xml"
        path.parent.mkdir(exist_ok=True)
        path.write_text("<testsuite><testcase name='contract'/></testsuite>")

    monkeypatch.setattr(gate, "execute", execute)
    for _ in range(2):
        assert gate.run_gate(tmp_path, "properties", SELECTED, "schedule") == 0
    assert executions[0] == executions[1]
    report = json.loads((tmp_path / "build/quality-receipts/properties.json").read_text())
    assert report["seed"].isdigit()
    assert report["seed"] in executions[0]
    monkeypatch.setattr(gate, "context", lambda: {**BINDING, "run_id": "18"})
    assert gate.run_gate(tmp_path, "properties", SELECTED, "schedule") == 0
    assert executions[-1] != executions[0]


@pytest.fixture
def policy_repo(tmp_path, monkeypatch):
    (tmp_path / "backend/tests").mkdir(parents=True)
    (tmp_path / "backend/tests/test_rule.py").write_text("def test_original(): pass\n")
    (tmp_path / "Makefile").write_text("check:\n\tfalse\n")
    original = {
        "backend/tests/test_rule.py": b"def test_original(): pass\n",
        "Makefile": b"check:\n\tfalse\n",
    }
    monkeypatch.setattr(policy, "previous_source", lambda root, base, name: original.get(name, b""))
    return tmp_path, "fixture-base"


def test_policy_detects_removed_regression_and_changed_gate(policy_repo):
    root, base = policy_repo
    (root / "backend/tests/test_rule.py").write_text("def test_other(): pass\n")
    (root / "Makefile").write_text("check:\n\ttrue\n")
    paths = ["Makefile", "backend/tests/test_rule.py"]
    required = policy.obligations(root, base, paths)
    assert "removed test cases: test_original" in required["backend/tests/test_rule.py"]["reasons"]
    assert len(policy.check_records(root, required, paths)) == 2


def test_policy_record_is_bound_to_changed_source_bytes(policy_repo):
    root, base = policy_repo
    (root / "Makefile").write_text("check:\n\ttrue\n")
    required = policy.obligations(root, base, ["Makefile"])
    record = {
        "schema": "vpw.quality-change.v1",
        "owner": "@maintainer",
        "reason": "Retired fixture requirement",
        "risk": "Removed obsolete gate",
        "validation": "Explicit replacement contract passes",
        "coverage_impact": "Current supported behavior stays covered",
        "paths": {"Makefile": required["Makefile"]["sha256"]},
    }
    path = root / "quality/reviews/change.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(record))
    paths = ["Makefile", "quality/reviews/change.json"]
    assert policy.check_records(root, required, paths) == []
    (root / "Makefile").write_text("check:\n\tfalse\n")
    revised = policy.obligations(root, base, paths)
    assert any("stale source hash" in error for error in policy.check_records(root, revised, paths))


def history_receipt(value=10, profile="extended"):
    return {
        "gate": "history",
        "profile": profile,
        "status": "passed",
        "environment": {
            "python": "3.14.6",
            "system": "Linux",
            "machine": "x86_64",
            "runner_image": "ubuntu24",
        },
        "metrics": {
            "rows": 1000,
            "cycles": 6,
            "page_seconds": value,
            "page_bytes": 100,
            "report_seconds": value,
            "peak_rss_mib": value,
            "database_bytes_per_revision": value,
            "budgets": {
                key: 1000
                for key in (
                    "page_seconds",
                    "page_bytes",
                    "report_seconds",
                    "peak_rss_mib",
                    "database_bytes_per_revision",
                )
            },
        },
    }


def campaign(receipt):
    return {"context": BINDING, "contracts": {"history": receipt}}


def test_trends_require_comparable_sustained_deterioration():
    current = campaign(history_receipt(13))
    previous = [campaign(history_receipt(n)) for n in (13, 13, 10, 10, 10)]
    assert trends.analyze(current, previous)["status"] == "warning"
    previous[0] = campaign(history_receipt(10))
    assert trends.analyze(current, previous)["status"] == "healthy"
    previous = [campaign(history_receipt(10, "ci")) for _ in range(5)]
    assert trends.analyze(current, previous)["status"] == "calibrating"


def test_trends_warn_before_absolute_budget_is_exceeded():
    current = campaign(history_receipt(905))
    result = trends.analyze(current, [])
    assert result["status"] == "warning"
    assert any("90%" in warning for warning in result["warnings"])


def test_test_scope_loss_is_visible_even_when_every_remaining_test_passes():
    current = receipts()[0]
    current.update(profile="ci", environment=history_receipt()["environment"])
    current["metrics"] = {"tests": 8}
    old = copy.deepcopy(current)
    old["metrics"]["tests"] = 10
    result = trends.analyze(
        {"context": BINDING, "contracts": {"core": current}},
        [{"contracts": {"core": old}}],
    )
    assert any("checked tests decreased" in warning for warning in result["warnings"])


NOW = datetime(2030, 1, 20, tzinfo=UTC)


def workflow_run(age=1, conclusion="success", event="schedule"):
    stamp = (NOW - timedelta(days=age)).isoformat()
    return {
        "id": 1,
        "head_branch": "main",
        "event": event,
        "created_at": stamp,
        "updated_at": stamp,
        "status": "completed",
        "conclusion": conclusion,
        "html_url": "https://github.com/owner/repo/actions/runs/1",
    }


@pytest.mark.parametrize(
    "runs,state",
    [
        ([], "active"),
        ([workflow_run(11)], "active"),
        ([workflow_run(event="pull_request")], "active"),
        ([workflow_run(0, "failure"), workflow_run(1)], "active"),
        ([workflow_run()], "disabled_inactivity"),
    ],
)
def test_health_detects_missing_stale_failed_and_disabled_campaigns(runs, state):
    assert health.assess_workflow("quality", state, runs, NOW)


def test_health_allows_recovery_only_after_a_new_successful_main_campaign():
    assert (
        health.assess_workflow(
            "quality", "active", [workflow_run(), workflow_run(2, "failure")], NOW
        )
        == []
    )


def test_health_detects_a_stuck_campaign():
    run = workflow_run()
    run.update(status="in_progress", conclusion=None)
    errors = health.assess_workflow("quality", "active", [run, workflow_run(2)], NOW)
    assert any("two hours" in error for error in errors)


def test_protection_audit_rejects_missing_gate_and_admin_bypass():
    assert health.protection_errors({}) == [
        "main: missing required checks: " + ", ".join(sorted(health.REQUIRED_CHECKS)),
        "main: up-to-date branch checks are not enforced",
        "main: administrators can bypass the protection",
        "main: allow_force_pushes protection has drifted",
        "main: allow_deletions protection has drifted",
    ]


def test_new_critical_entry_point_requires_a_coverage_decision(policy_repo):
    root, base = policy_repo
    path = root / "backend/app/decision_core/new_rule.py"
    path.parent.mkdir(parents=True)
    path.write_text("def decide(): return True\n")
    required = policy.obligations(root, base, ["backend/app/decision_core/new_rule.py"])
    assert "new critical module" in required[str(path.relative_to(root))]["reasons"][0]


def test_unreadable_monitoring_never_reports_healthy(monkeypatch):
    def unavailable(*args):
        raise subprocess.CalledProcessError(1, ["gh", "api"])

    monkeypatch.setattr(health, "github", unavailable)
    report = health.inspect("owner/repo", check_protection=True)
    assert report["status"] == "attention"
    assert len(report["errors"]) == 5


def test_github_client_rejects_arbitrary_urls():
    with pytest.raises(ValueError):
        trends.repository("https://example.invalid/collect")


def test_artifact_reader_requires_the_named_bounded_member(monkeypatch):
    import io
    import zipfile
    from types import SimpleNamespace

    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("../quality-metrics.json", "{}")
    monkeypatch.setattr(
        trends.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=data.getvalue())
    )
    with pytest.raises(ValueError, match="Missing"):
        trends.artifact("owner/repo", 12, "quality-metrics.json")


def test_release_build_waits_for_the_same_candidate_quality_workflow():
    import yaml
    from paths import REPO_ROOT

    workflow = yaml.safe_load((REPO_ROOT / ".github/workflows/release.yml").read_text())
    jobs = workflow["jobs"]
    assert jobs["build-and-release"]["needs"] == "quality"
    assert jobs["quality"]["uses"] == "./.github/workflows/test-quality.yml"
    quality = yaml.safe_load((REPO_ROOT / ".github/workflows/test-quality.yml").read_text())
    admission = quality["jobs"]["admission"]
    assert admission["if"] == "always()"
    assert set(admission["needs"]) == {"selection", "policy", "contracts"}
    assert admission["name"] == "quality-gate"
