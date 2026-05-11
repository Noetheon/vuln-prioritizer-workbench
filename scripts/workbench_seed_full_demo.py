"""Seed a fuller local Workbench demo project through the public API.

This script is intentionally frontend/backend-contract only: it does not write
directly to the database and it does not require backend internals.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_API_URL = "http://127.0.0.1:8000/api/v1"
DEFAULT_FRONTEND_URL = "http://127.0.0.1:5173"


@dataclass(frozen=True)
class ImportSpec:
    input_type: str
    file_path: Path
    asset_context: bool = False
    vex: bool = False


class ApiClient:
    def __init__(self, base_url: str, token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        request_headers = dict(headers or {})
        if self.token:
            request_headers.setdefault("Authorization", f"Bearer {self.token}")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=request_headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{path} failed with HTTP {exc.code}: {detail}") from exc


def main() -> None:
    args = parse_args()
    api = ApiClient(args.api_url)
    api.token = login(api, email=args.email, password=args.password)
    project = create_project(api, args.project_name)
    project_id = str(project["id"])

    import_results = seed_imports(api, project_id)
    if not import_results:
        raise RuntimeError("No demo imports succeeded; cannot finish full demo seed.")

    seed_assets(api, project_id)
    findings = api.request(f"/projects/{project_id}/findings/?limit=500&sort=operational")
    seed_waivers(api, project_id, findings.get("data", []))
    seed_api_token(api, project_id)
    seed_provider_job(api)
    seed_reports(api, import_results)

    summary = api.request(f"/projects/{project_id}/summary")
    assets = api.request(f"/projects/{project_id}/assets/")
    waivers = api.request(f"/projects/{project_id}/waivers/")
    runs = api.request(f"/projects/{project_id}/runs/")

    frontend = args.frontend_url.rstrip("/")
    result = {
        "project_id": project_id,
        "project_name": project["name"],
        "findings": summary.get("finding_count", 0),
        "runs": runs.get("count", 0),
        "assets": assets.get("count", 0),
        "waivers": waivers.get("count", 0),
        "urls": {
            "dashboard": f"{frontend}/?projectId={project_id}",
            "imports": f"{frontend}/imports?projectId={project_id}",
            "findings": f"{frontend}/findings?projectId={project_id}",
            "assets": f"{frontend}/assets?projectId={project_id}",
            "waivers": f"{frontend}/waivers?projectId={project_id}",
            "reports": f"{frontend}/reports?projectId={project_id}",
            "providers": f"{frontend}/providers?projectId={project_id}",
            "settings": f"{frontend}/settings?projectId={project_id}",
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", default=os.environ.get("VPW_API_URL", DEFAULT_API_URL))
    parser.add_argument(
        "--frontend-url",
        default=os.environ.get("VPW_FRONTEND_URL", DEFAULT_FRONTEND_URL),
    )
    parser.add_argument("--email", default=os.environ.get("FIRST_SUPERUSER", "admin@example.com"))
    parser.add_argument(
        "--password",
        default=os.environ.get(
            "FIRST_SUPERUSER_PASSWORD",
            "local-workbench-dev-password",
        ),
    )
    parser.add_argument(
        "--project-name",
        default=f"VPW Full Demo Workbench {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    return parser.parse_args()


def login(api: ApiClient, *, email: str, password: str) -> str:
    payload = urllib.parse.urlencode({"username": email, "password": password}).encode()
    response = api.request(
        "/login/access-token",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return str(response["access_token"])


def create_project(api: ApiClient, name: str) -> dict[str, Any]:
    return api.request(
        "/projects/",
        data=json.dumps(
            {
                "name": name,
                "description": (
                    "Seeded demo project with imports, findings, reports, assets, "
                    "waivers and evidence artifacts."
                ),
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
    )


def seed_imports(api: ApiClient, project_id: str) -> list[dict[str, Any]]:
    specs = [
        ImportSpec(
            input_type="trivy-json",
            file_path=REPO_ROOT / "data/input_fixtures/trivy_report.json",
            asset_context=True,
            vex=True,
        ),
        ImportSpec(
            input_type="generic-occurrence-csv",
            file_path=REPO_ROOT / "data/input_fixtures/generic_occurrences.csv",
            vex=True,
        ),
        ImportSpec(input_type="cve-list", file_path=REPO_ROOT / "data/sample_cves.txt"),
        ImportSpec(
            input_type="github-alerts-json",
            file_path=REPO_ROOT / "data/input_fixtures/github_alerts_export.json",
        ),
        ImportSpec(
            input_type="dependency-check-json",
            file_path=REPO_ROOT / "data/input_fixtures/dependency_check_report.json",
        ),
        ImportSpec(
            input_type="grype-json",
            file_path=REPO_ROOT / "data/input_fixtures/grype_report.json",
            asset_context=True,
            vex=True,
        ),
        ImportSpec(
            input_type="cyclonedx-json",
            file_path=REPO_ROOT / "data/input_fixtures/cyclonedx_bom.json",
            vex=True,
        ),
        ImportSpec(
            input_type="spdx-json",
            file_path=REPO_ROOT / "data/input_fixtures/spdx_bom.json",
            vex=True,
        ),
        ImportSpec(
            input_type="nessus-xml",
            file_path=REPO_ROOT / "data/input_fixtures/nessus_report.nessus",
        ),
        ImportSpec(
            input_type="openvas-xml",
            file_path=REPO_ROOT / "data/input_fixtures/openvas_report.xml",
        ),
    ]
    runs: list[dict[str, Any]] = []
    for spec in specs:
        try:
            runs.append(import_fixture(api, project_id, spec))
        except RuntimeError as exc:
            print(f"warning: skipped {spec.input_type}: {exc}", file=sys.stderr)
    return runs


def import_fixture(api: ApiClient, project_id: str, spec: ImportSpec) -> dict[str, Any]:
    fields = {
        "input_type": spec.input_type,
        "provider_snapshot_file": "demo_provider_snapshot.json",
        "locked_provider_data": "true",
        "attack_source": "none",
    }
    files = {"file": spec.file_path}
    if spec.asset_context:
        files["asset_context_file"] = REPO_ROOT / "data/input_fixtures/example_asset_context.csv"
    if spec.vex:
        files["vex_file"] = REPO_ROOT / "data/input_fixtures/openvex_statements.json"
    body, boundary = multipart_body(fields, files)
    return api.request(
        f"/projects/{project_id}/imports",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )


def multipart_body(fields: dict[str, str], files: dict[str, Path]) -> tuple[bytes, str]:
    boundary = f"vpw-demo-{uuid4().hex}"
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        )
    for name, path in files.items():
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        parts.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"; filename="{path.name}"\r\n'
                ).encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                path.read_bytes(),
                b"\r\n",
            ]
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), boundary


def seed_assets(api: ApiClient, project_id: str) -> None:
    assets = [
        {
            "asset_key": "api-gateway",
            "name": "API Gateway",
            "target_ref": "ghcr.io/acme/demo-app:1.0.0 (alpine 3.19)",
            "owner": "platform-team",
            "business_service": "customer-login",
            "environment": "production",
            "exposure": "internet-facing",
            "criticality": "critical",
        },
        {
            "asset_key": "web-tier",
            "name": "Checkout Web Tier",
            "target_ref": "web-tier",
            "owner": "team-web",
            "business_service": "checkout",
            "environment": "production",
            "exposure": "internet-facing",
            "criticality": "high",
        },
        {
            "asset_key": "build-host-1",
            "name": "Build Host 1",
            "target_ref": "build-host-1",
            "owner": "team-platform",
            "business_service": "payments",
            "environment": "production",
            "exposure": "internal",
            "criticality": "high",
        },
    ]
    for asset in assets:
        api.request(
            f"/projects/{project_id}/assets/",
            data=json.dumps(asset).encode(),
            headers={"Content-Type": "application/json"},
        )


def seed_waivers(api: ApiClient, project_id: str, findings: list[dict[str, Any]]) -> None:
    expires = (datetime.now(UTC).date() + timedelta(days=45)).isoformat()
    review = datetime.now(UTC).date().isoformat()
    if findings:
        api.request(
            f"/projects/{project_id}/waivers/",
            data=json.dumps(
                {
                    "finding_id": findings[0]["id"],
                    "owner": "risk-review",
                    "reason": "Demo accepted risk while rollout evidence is reviewed.",
                    "expires_at": expires,
                    "review_at": review,
                    "approval_ref": "DEMO-APPROVAL-001",
                    "ticket_url": "https://example.com/security/DEMO-APPROVAL-001",
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
    api.request(
        f"/projects/{project_id}/waivers/",
        data=json.dumps(
            {
                "service": "payments",
                "owner": "platform-risk",
                "reason": "Demo service-level risk acceptance for staged remediation.",
                "expires_at": expires,
                "review_at": review,
                "approval_ref": "DEMO-APPROVAL-002",
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
    )


def seed_api_token(api: ApiClient, project_id: str) -> None:
    api.request(
        "/api-tokens/",
        data=json.dumps(
            {
                "name": "Demo CI import token",
                "scopes": ["read", "import", "report"],
                "project_id": project_id,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
    )


def seed_provider_job(api: ApiClient) -> None:
    api.request(
        "/providers/update-jobs",
        data=json.dumps(
            {
                "sources": ["kev"],
                "cve_ids": ["CVE-2024-3094"],
                "cache_only": True,
                "max_cves": 1,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
    )


def seed_reports(api: ApiClient, runs: list[dict[str, Any]]) -> None:
    report_formats = ["markdown", "html", "json", "csv", "attack-navigator", "sarif", "zip"]
    report_runs = [run for run in runs if run.get("input_type") in {"trivy-json", "cve-list"}][:2]
    for run in report_runs:
        for report_format in report_formats:
            try:
                api.request(
                    f"/runs/{run['id']}/reports",
                    data=json.dumps({"format": report_format}).encode(),
                    headers={"Content-Type": "application/json"},
                )
            except RuntimeError as exc:
                print(
                    f"warning: skipped {report_format} report for {run['id']}: {exc}",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    main()
