"""Validate the Docker Compose quickstart login and locked-snapshot import path."""

from __future__ import annotations

import json
import mimetypes
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4

BASE_URL = os.environ.get("DOCKER_QUICKSTART_API_BASE_URL", "http://127.0.0.1:8000/api/v1").rstrip(
    "/"
)
REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CVES = REPO_ROOT / "data" / "sample_cves.txt"


def main() -> None:
    token = _login()
    workbench_status = _get_workbench_status(token)
    project_id = _create_project(token)
    run = _import_demo(token, project_id)
    findings = _get_findings(token, project_id)
    provider_job = _trigger_provider_update(token)
    provider_status = _get_provider_status(token)

    summary = run.get("summary_json") or {}
    if run.get("status") not in {"succeeded", "completed"}:
        raise RuntimeError(f"Demo import did not complete: {run.get('status')!r}")
    if not findings:
        raise RuntimeError("Demo import returned no findings.")
    if workbench_status.get("database_status") != "ready":
        raise RuntimeError(f"Database readiness failed: {workbench_status!r}")
    if workbench_status.get("schema_status") != "ready":
        raise RuntimeError(f"Schema readiness failed: {workbench_status!r}")
    if summary.get("locked_provider_data") is not True:
        raise RuntimeError("Demo import did not use locked provider data.")
    provider_snapshot_ref = str(summary.get("provider_snapshot_file", ""))
    provider_snapshot_ref_normalized = provider_snapshot_ref.replace("\\", "/")
    if provider_snapshot_ref_normalized.startswith("/") or ":/" in provider_snapshot_ref_normalized:
        raise RuntimeError(
            f"Demo import leaked an absolute provider snapshot path: {provider_snapshot_ref!r}"
        )
    if not provider_snapshot_ref_normalized.endswith("demo_provider_snapshot.json"):
        raise RuntimeError(
            "Demo import did not use the Compose-mounted provider snapshot: "
            f"{provider_snapshot_ref!r}"
        )
    if provider_job.get("status") not in {"succeeded", "completed"}:
        raise RuntimeError(f"Provider update job did not complete: {provider_job!r}")
    if provider_status.get("latest_update_job", {}).get("id") != provider_job.get("id"):
        raise RuntimeError("Provider status did not surface the latest update job.")
    if provider_status.get("snapshot", {}).get("mode") != "cache-only":
        raise RuntimeError(
            "Provider update did not produce a cache-only snapshot: "
            f"{provider_status.get('snapshot')!r}"
        )

    print(
        "Workbench demo import passed: "
        f"project_id={project_id} run_id={run['id']} findings={len(findings)} "
        f"locked_provider_data={summary['locked_provider_data']} "
        f"provider_job_id={provider_job['id']}"
    )


def _login() -> str:
    password = os.environ.get("FIRST_SUPERUSER_PASSWORD", "local-workbench-dev-password")
    payload = urllib.parse.urlencode(
        {"username": "admin@example.com", "password": password}
    ).encode()
    response = _request(
        f"{BASE_URL}/login/access-token",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return str(response["access_token"])


def _get_workbench_status(token: str) -> dict[str, object]:
    return _request(
        f"{BASE_URL}/workbench/status",
        headers={"Authorization": f"Bearer {token}"},
    )


def _create_project(token: str) -> str:
    payload = json.dumps(
        {
            "name": f"docker-quickstart-{uuid4().hex[:8]}",
            "description": "VPW-075 Docker Compose quickstart smoke",
        }
    ).encode()
    response = _request(
        f"{BASE_URL}/projects/",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    return str(response["id"])


def _import_demo(token: str, project_id: str) -> dict[str, object]:
    boundary = f"vpw-{uuid4().hex}"
    body = _multipart_body(
        boundary=boundary,
        fields={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={
            "file": SAMPLE_CVES,
        },
    )
    return _request(
        f"{BASE_URL}/projects/{project_id}/imports",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )


def _get_findings(token: str, project_id: str) -> list[dict[str, object]]:
    response = _request(
        f"{BASE_URL}/projects/{project_id}/findings/?sort=cve",
        headers={"Authorization": f"Bearer {token}"},
    )
    findings = response.get("data")
    if not isinstance(findings, list):
        raise RuntimeError("Findings API did not return a data list.")
    return findings


def _trigger_provider_update(token: str) -> dict[str, object]:
    payload = json.dumps(
        {
            "sources": ["kev"],
            "cve_ids": ["CVE-2024-3094"],
            "cache_only": True,
            "max_cves": 1,
        }
    ).encode()
    return _request(
        f"{BASE_URL}/providers/update-jobs",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )


def _get_provider_status(token: str) -> dict[str, object]:
    return _request(
        f"{BASE_URL}/providers/status",
        headers={"Authorization": f"Bearer {token}"},
    )


def _request(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{url} failed with HTTP {exc.code}: {detail}") from exc


def _multipart_body(
    *,
    boundary: str,
    fields: dict[str, str],
    files: dict[str, Path],
) -> bytes:
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
        filename = path.name
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        parts.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                ).encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                path.read_bytes(),
                b"\r\n",
            ]
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


if __name__ == "__main__":
    main()
