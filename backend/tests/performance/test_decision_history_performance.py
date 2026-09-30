"""Bound decision-history growth through real imports, evaluations, reads and reports."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import platform
import resource
import subprocess
import sys
import time
from pathlib import Path

import pytest
from paths import REPO_ROOT
from sqlmodel import Session, func, select
from utils.decision_scenarios import DecisionScenario
from utils.workbench_env import WorkbenchApiEnv

from app.models import FindingDecisionEvidence, FindingOccurrence

pytestmark = pytest.mark.performance


def _digest(value: object) -> str:
    digest = hashlib.sha256()
    for chunk in json.JSONEncoder(sort_keys=True).iterencode(value):
        digest.update(chunk.encode())
    return digest.hexdigest()


def _rss_mib() -> float:
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / divisor


def test_history_growth_preserves_bounded_current_reads_and_recorded_reports(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    if os.environ.get("VPW_HISTORY_PERFORMANCE") != "1":
        pytest.skip("Enable with make history-performance-check")
    profile = os.environ.get("VPW_HISTORY_PROFILE", "ci")
    assert profile in {"ci", "extended"}, "Unknown history performance profile"
    compressed = profile == "extended"
    rows, cycles = (1000, 6) if profile == "extended" else (200, 3)
    # Fixed ceilings; changing these requires a documented baseline comparison.
    budgets = {
        "operation_seconds": 60,
        "page_seconds": 1,
        "report_seconds": 30,
        "page_bytes": 1024 * 1024,
        "report_expanded_bytes_per_finding": 65536,
        "report_artifact_bytes_per_finding": 4096 if compressed else 65536,
        "database_bytes_per_revision": 16000,
        "peak_rss_mib": 768,
    }
    output = REPO_ROOT / "build" / f"history-performance-{profile}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    metrics: dict = {
        "schema": "vpw.history-performance.v1",
        "profile": profile,
        "status": "failed",
        "python": sys.version,
        "platform": platform.platform(),
        "storage": "file-backed-sqlite",
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip(),
        "report_format": "json-gzip" if compressed else "json",
        "rows": rows,
        "cycles": cycles,
        "budgets": budgets,
        "stages": [],
    }
    started = time.perf_counter()
    try:
        env = file_backed_workbench_api_env
        assert env.engine.url.database and env.engine.url.database != ":memory:"
        scenario = DecisionScenario(env, tmp_path)
        start = time.perf_counter()
        original = scenario.import_rows(rows)
        metrics["initial_import_seconds"] = time.perf_counter() - start
        initial_report = scenario.analysis_report(original["id"], compressed=compressed)[0]
        report_digest = _digest(initial_report["findings"])
        del initial_report
        selected = scenario.findings()[0]["id"]
        last_observed = scenario.detail(selected)["last_seen_at"]
        for cycle in range(cycles):
            stage: dict = {"cycle": cycle + 1}
            metrics["stages"].append(stage)
            start = time.perf_counter()
            reevaluation = scenario.evaluate()
            stage["reevaluation_seconds"] = time.perf_counter() - start
            stage["rss_after_reevaluation_mib"] = _rss_mib()
            assert scenario.detail(selected)["last_seen_at"] == last_observed
            assert reevaluation["updated_findings"] == rows
            start = time.perf_counter()
            imported = scenario.import_rows(rows, context=False)
            stage["reimport_seconds"] = time.perf_counter() - start
            assert imported["created_findings"] == 0 and imported["updated_findings"] == rows
            last_observed = scenario.detail(selected)["last_seen_at"]
            samples = []
            for _ in range(3):
                start = time.perf_counter()
                page = env.client.get(
                    f"/api/v1/projects/{scenario.project_id}/findings/",
                    params={"offset": rows - 100, "limit": 100, "sort": "cve"},
                )
                samples.append(time.perf_counter() - start)
                assert page.status_code == 200, page.text
                assert page.json()["count"] == rows
                assert len({item["id"] for item in page.json()["data"]}) == 100
            stage["page_seconds"] = max(samples)
            stage["page_bytes"] = len(page.content)
            start = time.perf_counter()
            regenerated, raw = scenario.analysis_report(original["id"], compressed=compressed)
            stage["report_seconds"] = time.perf_counter() - start
            stage["rss_after_report_mib"] = _rss_mib()
            stage["report_bytes"] = len(raw)
            stage["report_expanded_bytes"] = len(gzip.decompress(raw)) if compressed else len(raw)
            assert _digest(regenerated["findings"]) == report_digest
            del regenerated, raw
            with Session(env.engine) as session:
                stage["revision_count"] = session.exec(
                    select(func.count()).select_from(FindingDecisionEvidence)
                ).one()
                stage["observation_count"] = session.exec(
                    select(func.count()).select_from(FindingOccurrence)
                ).one()
                stage["database_bytes"] = (
                    session.connection().exec_driver_sql("PRAGMA page_count").scalar_one()
                    * session.connection().exec_driver_sql("PRAGMA page_size").scalar_one()
                )
            assert stage["revision_count"] == rows * (1 + 2 * (cycle + 1))
            assert stage["observation_count"] == rows * (cycle + 2)
            stage["database_bytes_per_revision"] = stage["database_bytes"] / stage["revision_count"]
            stage["peak_rss_mib"] = _rss_mib()
        # Record the complete workload before applying budgets for useful diagnostics.
        assert metrics["initial_import_seconds"] <= budgets["operation_seconds"], metrics
        for stage in metrics["stages"]:
            for field in ("reevaluation_seconds", "reimport_seconds"):
                assert stage[field] <= budgets["operation_seconds"], stage
            for field in (
                "page_seconds",
                "report_seconds",
                "page_bytes",
                "database_bytes_per_revision",
                "peak_rss_mib",
            ):
                assert stage[field] <= budgets[field], stage
            assert stage["report_bytes"] <= rows * budgets["report_artifact_bytes_per_finding"], (
                stage
            )
            assert (
                stage["report_expanded_bytes"]
                <= rows * budgets["report_expanded_bytes_per_finding"]
            ), stage
        assert metrics["stages"][-1]["page_bytes"] <= metrics["stages"][0]["page_bytes"] * 1.1
        metrics["status"] = "passed"
    finally:
        metrics["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        output.write_text(json.dumps(metrics, indent=2) + "\n")
