"""Retain comparable quality measurements and surface sustained deterioration."""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import re
import statistics
import subprocess
import zipfile
from pathlib import Path

from scripts.quality_gate import read_json, write_json


def repository(value: str) -> str:
    """Accept a GitHub owner/repository name, never an arbitrary API URL."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("Expected owner/repository")
    return value


def github(repo: str, endpoint: str) -> dict:
    """Use the runner's read-only GitHub credential without logging it."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repository(repo)}/{endpoint}"],
        capture_output=True,
        check=True,
        timeout=45,
    )
    return json.loads(result.stdout)


def artifact(repo: str, artifact_id: int, filename: str) -> dict:
    """Read one bounded JSON member without extracting untrusted archive paths."""
    if type(artifact_id) is not int or artifact_id <= 0:
        raise ValueError("Invalid artifact id")
    result = subprocess.run(
        ["gh", "api", f"repos/{repository(repo)}/actions/artifacts/{artifact_id}/zip"],
        capture_output=True,
        check=True,
        timeout=45,
    )
    if len(result.stdout) > 10_000_000:
        raise ValueError("Oversized metrics archive")
    with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
        matches = [info for info in archive.infolist() if info.filename == filename]
        if len(matches) != 1 or matches[0].file_size > 5_000_000:
            raise ValueError("Missing, duplicate or oversized metrics member")
        value = json.loads(archive.read(matches[0]))
    if not isinstance(value, dict):
        raise ValueError("Invalid metrics document")
    return value


def previous_reports(repo: str, current_run: str) -> list[dict]:
    """Only successful main-branch campaigns can supply comparison baselines."""
    runs = github(
        repo, "actions/workflows/test-quality.yml/runs?branch=main&status=success&per_page=30"
    )["workflow_runs"]
    reports = []
    for run in runs:
        if str(run["id"]) == current_run or run["event"] not in {
            "push",
            "schedule",
            "workflow_dispatch",
        }:
            continue
        artifacts = github(repo, f"actions/runs/{run['id']}/artifacts?per_page=100")["artifacts"]
        candidates = [a for a in artifacts if a["name"] == "quality-metrics" and not a["expired"]]
        if not candidates:
            continue
        report = artifact(repo, candidates[0]["id"], "quality-metrics.json")
        binding = report.get("context", {})
        if (
            report.get("schema") != "vpw.quality-metrics.v1"
            or binding.get("sha") != run["head_sha"]
            or binding.get("run_id") != str(run["id"])
            or binding.get("repository") != repo
        ):
            raise ValueError("Historical metrics do not match their GitHub run")
        reports.append(report)
        if len(reports) == 8:
            break
    return reports


def comparable(current: dict, previous: dict) -> bool:
    """Separate profiles, workload sizes, interpreters and runner families."""

    def key(item: dict) -> tuple:
        env = item["environment"]
        measurement = item["metrics"]
        return (
            item["gate"],
            item["profile"],
            ".".join(env["python"].split(".")[:2]),
            env["system"],
            env["machine"],
            env["runner_image"],
            measurement.get("rows"),
            measurement.get("cycles"),
            measurement.get("mutmut"),
        )

    return previous.get("status") == "passed" and key(current) == key(previous)


def analyze(current: dict, history: list[dict]) -> dict:
    """Warn on scope loss, approaching budgets, or three sustained slower runs."""
    warnings = []
    baselines = {}
    for gate, receipt in current["contracts"].items():
        if receipt["status"] != "passed":
            continue
        measure = receipt["metrics"]
        peers = [
            report["contracts"][gate]
            for report in history
            if gate in report.get("contracts", {})
            and comparable(receipt, report["contracts"][gate])
        ]
        baselines[gate] = len(peers)
        if peers:
            for key in ("tests", "functions", "mutants"):
                if key in measure and measure[key] < peers[0]["metrics"][key]:
                    warnings.append(f"{gate}: checked {key} decreased; review the scope change.")
        if gate != "history":
            continue
        for key in (
            "page_seconds",
            "page_bytes",
            "report_seconds",
            "peak_rss_mib",
            "database_bytes_per_revision",
        ):
            value = measure[key]
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError(f"Invalid metric: {key}")
            if value >= measure["budgets"][key] * 0.9:
                warnings.append(f"history: {key} reached at least 90% of its fixed budget.")
            if len(peers) >= 5:
                # History is newest first: three older values establish a baseline;
                # current plus the two newest peers must all exceed it by 20%.
                baseline = statistics.median(p["metrics"][key] for p in peers[2:5])
                recent = [value, *(p["metrics"][key] for p in peers[:2])]
                if baseline > 0 and all(number > baseline * 1.2 for number in recent):
                    warnings.append(
                        f"history: {key} deteriorated by over 20% in three comparable runs."
                    )
    return {
        "schema": "vpw.quality-trends.v1",
        "context": current["context"],
        "status": "warning"
        if warnings
        else "calibrating"
        if any(n < 5 for n in baselines.values())
        else "healthy",
        "baseline_counts": baselines,
        "warnings": warnings,
    }


def main() -> int:
    """Write warnings separately from deterministic pass/fail contract results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, default=Path("build/quality-metrics.json"))
    parser.add_argument("--history", type=Path)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--output", type=Path, default=Path("build/quality-trends.json"))
    args = parser.parse_args()
    current = read_json(args.current)
    try:
        history = (
            [read_json(path) for path in sorted(args.history.glob("*.json"), reverse=True)]
            if args.history
            else previous_reports(args.repository, current["context"]["run_id"])
        )
        report = analyze(current, history)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        zipfile.BadZipFile,
        subprocess.SubprocessError,
    ) as error:
        report = {
            "schema": "vpw.quality-trends.v1",
            "context": current["context"],
            "status": "unavailable",
            "warnings": [f"Trend monitoring unavailable: {type(error).__name__}"],
        }
    write_json(args.output, report)
    lines = [f"Quality trends: {report['status']}", *report["warnings"]]
    for warning in report["warnings"]:
        print("::warning::" + warning)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a") as stream:
            stream.write("\n\n" + "\n\n".join(lines) + "\n")
    print("\n".join(lines))
    # Baseline/network problems are explicit monitoring incidents, not a reason
    # to mislabel a passing deterministic application contract as a failure.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
