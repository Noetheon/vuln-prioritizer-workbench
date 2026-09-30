"""Real API/worker scenarios shared by state, recovery, and history scale tests."""

from __future__ import annotations

import gzip
import json
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from paths import REPO_ROOT

from utils.import_contracts import completed_run_payload, drain_workflow_queue
from utils.workbench_contracts import _create_report_via_worker
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api


class DecisionScenario:
    """Own isolated artifact paths and an API-created project."""

    def __init__(self, env: WorkbenchApiEnv, root: Path, *, project_id: str | None = None) -> None:
        self.env = env
        self.root = root
        snapshots = root / "provider-snapshots"
        snapshots.mkdir(parents=True, exist_ok=True)
        if project_id is None:
            (snapshots / "demo.json").write_bytes(
                (REPO_ROOT / "backend/app/resources/demo_provider_snapshot.json").read_bytes()
            )
        env.client.app.state.workbench_settings = replace(
            env.client.app.state.workbench_settings,
            IMPORT_UPLOAD_DIR=str(root / "imports"),
            REPORT_DIR=str(root / "reports"),
            PROVIDER_CACHE_DIR=str(root / "provider-cache"),
            PROVIDER_SNAPSHOT_DIR=str(snapshots),
            MAX_REPORTS_PER_RUN=100,
        )
        self.project_id = (
            project_id or create_project_via_api(env.client, {}, name="Decision contract")["id"]
        )

    def import_rows(self, count: int, *, context: bool = True) -> dict[str, Any]:
        """Import independently scoped occurrences through the real worker."""
        header = "cve_id,target_ref,asset_id"
        if context:
            header += ",owner,business_service,exposure,environment,criticality"
        rows = [header]
        for index in range(count):
            row = f"CVE-2024-4577,web-{index},web-{index}"
            if context:
                row += ",original-owner,payments,internal,test,low"
            rows.append(row)
        response = self.env.client.post(
            f"/api/v1/projects/{self.project_id}/imports",
            data={
                "input_type": "generic-occurrence-csv",
                "provider_snapshot_file": "demo.json",
                "locked_provider_data": "true",
            },
            files={"file": ("observations.csv", "\n".join(rows).encode(), "text/csv")},
        )
        run = completed_run_payload(self.env, response, headers={})
        assert run["status"] == "succeeded", run
        return run

    def findings(self) -> list[dict[str, Any]]:
        """Read current finding summaries, following the public pagination contract."""
        rows = []
        offset = 0
        while True:
            response = self.env.client.get(
                f"/api/v1/projects/{self.project_id}/findings/",
                params={"offset": offset, "limit": 100},
            )
            assert response.status_code == 200, response.text
            payload = response.json()
            rows.extend(payload["data"])
            if len(rows) >= payload["count"]:
                return rows
            assert payload["data"], payload
            offset += len(payload["data"])

    def detail(self, finding_id: str) -> dict[str, Any]:
        response = self.env.client.get(f"/api/v1/findings/{finding_id}")
        assert response.status_code == 200, response.text
        return response.json()

    def evaluate(self, finding_ids: list[str] | None = None) -> dict[str, Any]:
        """Wait for terminal publication, rather than treating queue acceptance as success."""
        payload = {"finding_ids": finding_ids} if finding_ids is not None else {}
        response = self.env.client.post(
            f"/api/v1/projects/{self.project_id}/evaluations",
            json=payload,
        )
        assert response.status_code == 200, response.text
        workflow_id = response.json()["workflow"]["id"]
        run = completed_run_payload(self.env, response, headers={})
        workflow = self.env.client.get(f"/api/v1/workflows/{workflow_id}")
        assert workflow.status_code == 200, workflow.text
        assert workflow.json()["status"] == "succeeded", workflow.text
        assert run["status"] == "completed", run
        return run

    def analysis_report(
        self, run_id: str, *, compressed: bool = False
    ) -> tuple[dict[str, Any], bytes]:
        """Build a new historical report from recorded evidence via the worker."""
        report = _create_report_via_worker(
            self.env,
            uuid.UUID(run_id),
            headers={},
            payload={"format": "json-gzip" if compressed else "json"},
        )
        response = self.env.client.get(report["download_url"])
        assert response.status_code == 200, response.text
        return (
            json.loads(gzip.decompress(response.content)) if compressed else response.json()
        ), response.content

    def revision_counts(self) -> dict[str, int]:
        result = {}
        for finding in self.findings():
            response = self.env.client.get(f"/api/v1/findings/{finding['id']}/decision-revisions")
            assert response.status_code == 200, response.text
            result[finding["id"]] = response.json()["count"]
        return result

    def drain(self) -> None:
        drain_workflow_queue(self.env)
