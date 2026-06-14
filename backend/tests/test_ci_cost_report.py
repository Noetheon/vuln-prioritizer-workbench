from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "ci_cost_report.py"

spec = importlib.util.spec_from_file_location("ci_cost_report", SCRIPT_PATH)
assert spec is not None
ci_cost_report = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = ci_cost_report
spec.loader.exec_module(ci_cost_report)


def test_ci_cost_report_summarizes_job_minutes_and_percentiles() -> None:
    run = {
        "databaseId": 123,
        "event": "pull_request",
        "headBranch": "feature/ci",
        "createdAt": "2026-06-13T20:00:00Z",
    }
    jobs_payload = {
        "jobs": [
            {
                "name": "frontend",
                "startedAt": "2026-06-13T20:00:00Z",
                "completedAt": "2026-06-13T20:03:00Z",
            },
            {
                "name": "check (3.11)",
                "startedAt": "2026-06-13T20:00:30Z",
                "completedAt": "2026-06-13T20:02:00Z",
            },
        ],
    }

    summary = ci_cost_report.summarize_workflow_run("CI", run, jobs_payload)
    stats = ci_cost_report.workflow_stats([summary])

    assert summary.total_job_minutes == 4.5
    assert stats == {
        "runs": 1,
        "avg_job_minutes": 4.5,
        "median_job_minutes": 4.5,
        "p95_job_minutes": 4.5,
    }


def test_ci_cost_report_renders_markdown_and_json_payload() -> None:
    summaries = {
        "CI": [
            ci_cost_report.WorkflowRunSummary(
                workflow="CI",
                database_id=456,
                event="push",
                head_branch="main",
                created_at="2026-06-13T20:00:00Z",
                total_job_minutes=8.25,
                jobs=(
                    ci_cost_report.JobDuration("frontend", 5.0),
                    ci_cost_report.JobDuration("check (3.11)", 3.25),
                ),
            )
        ],
        "Docker": [],
    }

    markdown = ci_cost_report.render_markdown(
        summaries,
        generated_at=datetime(2026, 6, 13, 20, 0, tzinfo=UTC),
    )
    payload = ci_cost_report.serialize_summaries(summaries)

    assert "# CI Cost Report" in markdown
    assert "| CI | 1 | 8.25 | 8.25 | 8.25 | `456` `push` `main` |" in markdown
    assert "frontend: 5.00m" in markdown
    assert payload["CI"]["stats"]["runs"] == 1
    assert payload["CI"]["runs"][0]["jobs"][0] == {"name": "frontend", "minutes": 5.0}
    assert payload["Docker"]["stats"]["runs"] == 0
