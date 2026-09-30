"""Detect missing, failed or stale quality campaigns and protection drift."""

from __future__ import annotations

import argparse
import os
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.quality_gate import write_json
from scripts.quality_trends import artifact, github, repository

WORKFLOWS = ("test-quality.yml", "maintenance.yml", "provider-live.yml")
REQUIRED_CHECKS = {
    "Analyze Python",
    "check (3.11)",
    "check (3.12)",
    "compose-smoke",
    "frontend",
    "quality-gate",
}


def timestamp(value: str) -> datetime:
    """Require timezone-aware server times."""
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp has no timezone")
    return result


def assess_workflow(
    name: str, state: str, runs: list[dict], now: datetime, max_age_days: int = 10
) -> list[str]:
    """A later failed campaign or a missing successful heartbeat needs attention."""
    errors = []
    if state != "active":
        errors.append(f"{name}: workflow is {state}")
    eligible = sorted(
        [
            run
            for run in runs
            if run["head_branch"] == "main"
            and run["event"] in {"push", "schedule", "workflow_dispatch"}
        ],
        key=lambda run: timestamp(run["created_at"]),
        reverse=True,
    )
    completed = [run for run in eligible if run["status"] == "completed"]
    successes = [run for run in completed if run["conclusion"] == "success"]
    if not successes or now - timestamp(successes[0]["updated_at"]) > timedelta(days=max_age_days):
        errors.append(f"{name}: no successful full main-branch campaign within {max_age_days} days")
    if completed and completed[0]["conclusion"] != "success":
        errors.append(
            f"{name}: latest completed campaign is {completed[0]['conclusion']}: "
            f"{completed[0]['html_url']}"
        )
    for run in eligible[:3]:
        if run["status"] != "completed" and now - timestamp(run["created_at"]) > timedelta(hours=2):
            errors.append(f"{name}: campaign has not completed after two hours: {run['html_url']}")
    return errors


def protection_errors(protection: dict) -> list[str]:
    """Check additive required gates and preserve the existing merge protections."""
    checks = protection.get("required_status_checks") or {}
    present = {item["context"] for item in checks.get("checks", [])}
    errors = []
    if missing := REQUIRED_CHECKS - present:
        errors.append("main: missing required checks: " + ", ".join(sorted(missing)))
    if checks.get("strict") is not True:
        errors.append("main: up-to-date branch checks are not enforced")
    if protection.get("enforce_admins", {}).get("enabled") is not True:
        errors.append("main: administrators can bypass the protection")
    for key in ("allow_force_pushes", "allow_deletions"):
        if protection.get(key, {}).get("enabled") is not False:
            errors.append(f"main: {key} protection has drifted")
    return errors


def inspect(repo: str, *, check_protection: bool = False) -> dict:
    """Inspect authoritative GitHub state using read-only endpoints."""
    now = datetime.now(UTC)
    errors = []
    observed = {}
    monitored = (*WORKFLOWS, "quality-health.yml") if check_protection else WORKFLOWS
    for name in monitored:
        try:
            workflow = github(repo, f"actions/workflows/{name}")
            runs = github(repo, f"actions/workflows/{name}/runs?branch=main&per_page=50")[
                "workflow_runs"
            ]
            errors.extend(
                assess_workflow(
                    name,
                    workflow["state"],
                    runs,
                    now,
                    max_age_days=2 if name == "quality-health.yml" else 10,
                )
            )
            observed[name] = [
                {
                    key: run[key]
                    for key in ("id", "head_sha", "event", "status", "conclusion", "html_url")
                }
                for run in runs[:3]
            ]
            if name == "test-quality.yml":
                successful = next(
                    (
                        run
                        for run in runs
                        if run["status"] == "completed"
                        and run["conclusion"] == "success"
                        and run["head_branch"] == "main"
                        and run["event"] in {"push", "schedule", "workflow_dispatch"}
                    ),
                    None,
                )
                if successful:
                    artifacts = github(
                        repo, f"actions/runs/{successful['id']}/artifacts?per_page=100"
                    )["artifacts"]
                    item = next(
                        (
                            a
                            for a in artifacts
                            if a["name"] == "quality-metrics" and not a["expired"]
                        ),
                        None,
                    )
                    if item is None:
                        errors.append("test-quality.yml: compact monitoring evidence is missing")
                    else:
                        trend = artifact(repo, item["id"], "quality-trends.json")
                        if (
                            trend.get("schema") != "vpw.quality-trends.v1"
                            or trend.get("context", {}).get("repository") != repo
                            or trend.get("context", {}).get("sha") != successful["head_sha"]
                            or trend.get("context", {}).get("run_id") != str(successful["id"])
                        ):
                            raise ValueError("Trend evidence belongs to another execution")
                        if trend["status"] not in {"healthy", "calibrating"}:
                            errors.extend(
                                trend.get("warnings") or ["Quality trend needs attention"]
                            )
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            zipfile.BadZipFile,
            subprocess.SubprocessError,
        ) as error:
            errors.append(f"{name}: monitoring unavailable ({type(error).__name__})")
    if check_protection:
        try:
            errors.extend(protection_errors(github(repo, "branches/main/protection")))
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            errors.append(f"main: protection could not be verified ({type(error).__name__})")
    return {
        "schema": "vpw.quality-health.v1",
        "checked_at": now.isoformat(),
        "repository": repo,
        "status": "attention" if errors else "healthy",
        "protection_checked": check_protection,
        "errors": errors,
        "observed": observed,
    }


def main() -> int:
    """Fail visibly on stale runs; never treat unavailable monitoring as healthy."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--check-protection", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("build/quality-health.json"))
    args = parser.parse_args()
    repo = repository(args.repository)
    report = inspect(repo, check_protection=args.check_protection)
    write_json(args.output, report)
    lines = [f"Quality health: {report['status']}", *report["errors"]]
    print("\n".join(lines))
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a") as stream:
            stream.write("\n\n".join(lines) + "\n")
    return int(bool(report["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
