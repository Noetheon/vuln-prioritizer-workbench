"""Summarize GitHub Actions runner minutes for the repo's costly workflows."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_WORKFLOWS = ("CI", "Docker", "CodeQL")


@dataclass(frozen=True)
class JobDuration:
    """Measured duration for one GitHub Actions job."""

    name: str
    minutes: float


@dataclass(frozen=True)
class WorkflowRunSummary:
    """Aggregated job-minute data for one workflow run."""

    workflow: str
    database_id: int
    event: str
    head_branch: str
    created_at: str
    total_job_minutes: float
    jobs: tuple[JobDuration, ...]


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflow",
        action="append",
        dest="workflows",
        help="Workflow name to inspect. Defaults to CI, Docker, and CodeQL.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Successful runs to sample per workflow.",
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GH_REPO"),
        help="Optional owner/repo. Defaults to gh's current repository.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Optional path for machine-readable summary JSON.",
    )
    return parser.parse_args(argv)


def parse_github_datetime(value: str | None) -> datetime | None:
    """Parse a GitHub API timestamp into a timezone-aware datetime."""
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def job_minutes(job: dict[str, Any]) -> float:
    """Return the elapsed job duration in minutes."""
    started_at = parse_github_datetime(job.get("startedAt"))
    completed_at = parse_github_datetime(job.get("completedAt"))
    if started_at is None or completed_at is None:
        return 0.0
    return max((completed_at - started_at).total_seconds(), 0.0) / 60


def summarize_workflow_run(
    workflow: str,
    run: dict[str, Any],
    jobs_payload: dict[str, Any],
) -> WorkflowRunSummary:
    """Build a run summary from gh run and job payloads."""
    jobs = tuple(
        JobDuration(name=str(job.get("name", "<unnamed>")), minutes=job_minutes(job))
        for job in jobs_payload.get("jobs", [])
        if isinstance(job, dict)
    )
    return WorkflowRunSummary(
        workflow=workflow,
        database_id=int(run["databaseId"]),
        event=str(run.get("event", "")),
        head_branch=str(run.get("headBranch", "")),
        created_at=str(run.get("createdAt", "")),
        total_job_minutes=sum(job.minutes for job in jobs),
        jobs=jobs,
    )


def run_gh_json(args: list[str], *, repo: str | None) -> Any:
    """Run gh with JSON output and return the decoded payload."""
    command = ["gh", *args]
    if repo:
        command.extend(["--repo", repo])
    env = {**os.environ, "GH_PAGER": "cat"}
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )
    return json.loads(result.stdout)


def load_workflow_summaries(
    workflow: str,
    *,
    limit: int,
    repo: str | None,
) -> list[WorkflowRunSummary]:
    """Load recent successful runs for one workflow through gh."""
    runs = run_gh_json(
        [
            "run",
            "list",
            "--workflow",
            workflow,
            "--status",
            "success",
            "--limit",
            str(limit),
            "--json",
            "databaseId,event,headBranch,createdAt",
        ],
        repo=repo,
    )
    summaries: list[WorkflowRunSummary] = []
    for run in runs:
        jobs_payload = run_gh_json(
            [
                "run",
                "view",
                str(run["databaseId"]),
                "--json",
                "jobs",
            ],
            repo=repo,
        )
        summaries.append(summarize_workflow_run(workflow, run, jobs_payload))
    return summaries


def percentile(values: list[float], percentile_value: float) -> float:
    """Return an interpolated percentile for a list of numbers."""
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = (len(ordered) - 1) * percentile_value
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def workflow_stats(summaries: list[WorkflowRunSummary]) -> dict[str, float | int]:
    """Return aggregate job-minute statistics for workflow summaries."""
    totals = [summary.total_job_minutes for summary in summaries]
    return {
        "runs": len(totals),
        "avg_job_minutes": statistics.fmean(totals) if totals else 0.0,
        "median_job_minutes": statistics.median(totals) if totals else 0.0,
        "p95_job_minutes": percentile(totals, 0.95),
    }


def render_markdown(
    summaries_by_workflow: dict[str, list[WorkflowRunSummary]],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render workflow summaries as a GitHub-flavored Markdown report."""
    generated_at = generated_at or datetime.now(UTC)
    lines = [
        "# CI Cost Report",
        "",
        f"Generated at: `{generated_at.isoformat(timespec='seconds')}`",
        "",
        "| Workflow | Runs | Avg job-min | Median job-min | P95 job-min | Latest sampled run |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]

    for workflow, summaries in summaries_by_workflow.items():
        stats = workflow_stats(summaries)
        latest = summaries[0] if summaries else None
        latest_text = (
            f"`{latest.database_id}` `{latest.event}` `{latest.head_branch}`"
            if latest is not None
            else "-"
        )
        lines.append(
            "| {workflow} | {runs} | {avg:.2f} | {median:.2f} | {p95:.2f} | {latest} |".format(
                workflow=workflow,
                runs=stats["runs"],
                avg=stats["avg_job_minutes"],
                median=stats["median_job_minutes"],
                p95=stats["p95_job_minutes"],
                latest=latest_text,
            )
        )

    lines.extend(["", "## Recent Runs", ""])
    for workflow, summaries in summaries_by_workflow.items():
        lines.extend(
            [
                f"### {workflow}",
                "",
                "| Run | Event | Branch | Job-min | Largest jobs |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for summary in summaries[:10]:
            largest_jobs = sorted(summary.jobs, key=lambda job: job.minutes, reverse=True)[:4]
            largest_text = ", ".join(f"{job.name}: {job.minutes:.2f}m" for job in largest_jobs)
            lines.append(
                "| `{run}` | {event} | `{branch}` | {total:.2f} | {jobs} |".format(
                    run=summary.database_id,
                    event=summary.event,
                    branch=summary.head_branch,
                    total=summary.total_job_minutes,
                    jobs=largest_text or "-",
                )
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def serialize_summaries(
    summaries_by_workflow: dict[str, list[WorkflowRunSummary]],
) -> dict[str, Any]:
    """Return a machine-readable representation of workflow summaries."""
    return {
        workflow: {
            "stats": workflow_stats(summaries),
            "runs": [
                {
                    "database_id": summary.database_id,
                    "event": summary.event,
                    "head_branch": summary.head_branch,
                    "created_at": summary.created_at,
                    "total_job_minutes": round(summary.total_job_minutes, 4),
                    "jobs": [
                        {"name": job.name, "minutes": round(job.minutes, 4)} for job in summary.jobs
                    ],
                }
                for summary in summaries
            ],
        }
        for workflow, summaries in summaries_by_workflow.items()
    }


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    args = parse_args(argv or sys.argv[1:])
    workflows = tuple(args.workflows or DEFAULT_WORKFLOWS)
    summaries_by_workflow = {
        workflow: load_workflow_summaries(workflow, limit=args.limit, repo=args.repo)
        for workflow in workflows
    }
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(serialize_summaries(summaries_by_workflow), indent=2) + "\n",
            encoding="utf-8",
        )
    print(render_markdown(summaries_by_workflow), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
