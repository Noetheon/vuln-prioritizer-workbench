"""Validate the Docker Compose quickstart local Workbench import path."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

BASE_URL = os.environ.get("DOCKER_QUICKSTART_API_BASE_URL", "http://127.0.0.1:8000/api/v1").rstrip(
    "/"
)
REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CVES = REPO_ROOT / "data" / "sample_cves.txt"
REPORT_FORMATS = ("markdown", "html", "json", "csv", "sarif", "zip")
PRIVATE_PATH_PATTERN = re.compile(
    r"(/Users/|/private/|/tmp/|/app/(?:template|workbench)-|[A-Za-z]:\\\\)",
    re.IGNORECASE,
)


def main() -> None:
    """Exercise the Docker quickstart API path from project creation through reports."""
    workbench_status = _get_workbench_status()
    project_id = _create_project()
    run = _import_demo(project_id)
    summary = _get_run_summary(str(run["id"]))
    findings = _get_findings(project_id)
    reports = _create_reports(str(run["id"]))
    for report_format, report in reports.items():
        _download_report(report_format=report_format, report=report)
    provider_job = _trigger_provider_update()
    provider_status = _get_provider_status()

    if run.get("status") not in {"succeeded", "completed"}:
        raise RuntimeError(f"Demo import did not complete: {run.get('status')!r}")
    if summary.get("status") not in {"succeeded", "completed"}:
        raise RuntimeError(f"Demo import summary did not complete: {summary.get('status')!r}")
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
        f"reports={','.join(reports)} "
        f"locked_provider_data={summary['locked_provider_data']} "
        f"provider_job_id={provider_job['id']}"
    )


def _get_workbench_status() -> dict[str, object]:
    return _request(f"{BASE_URL}/workbench/status")


def _create_project() -> str:
    payload = json.dumps(
        {
            "name": f"docker-quickstart-{uuid4().hex[:8]}",
            "description": "VPW-075 Docker Compose quickstart smoke",
        }
    ).encode()
    response = _request(
        f"{BASE_URL}/projects/",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    return str(response["id"])


def _import_demo(project_id: str) -> dict[str, object]:
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
    response = _request(
        f"{BASE_URL}/projects/{project_id}/imports",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    _assert_no_private_paths(response)
    _assert_no_raw_workflow_fields(response)
    return response


def _get_run_summary(run_id: str) -> dict[str, object]:
    response = _request(f"{BASE_URL}/runs/{run_id}/summary")
    _assert_no_private_paths(response)
    _assert_no_raw_workflow_fields(response)
    return response


def _get_findings(project_id: str) -> list[dict[str, object]]:
    response = _request(
        f"{BASE_URL}/projects/{project_id}/findings/?sort=cve",
    )
    findings = response.get("data")
    if not isinstance(findings, list):
        raise RuntimeError("Findings API did not return a data list.")
    return findings


def _create_reports(run_id: str) -> dict[str, dict[str, object]]:
    reports: dict[str, dict[str, object]] = {}
    for report_format in REPORT_FORMATS:
        response = _request(
            f"{BASE_URL}/runs/{run_id}/reports",
            data=json.dumps({"format": report_format}).encode(),
            headers={"Content-Type": "application/json"},
        )
        _assert_no_private_paths(response)
        reports[report_format] = response
    return reports


def _download_report(*, report_format: str, report: dict[str, object]) -> None:
    report_id = str(report["id"])
    response = _raw_request(f"{BASE_URL}/reports/{report_id}/download")
    _assert_download_response(response, report=report)
    if report_format == "json":
        payload = json.loads(response.body.decode("utf-8"))
        _assert_no_private_paths(payload)
        if payload.get("schema") != "analysis-result.v1":
            raise RuntimeError(f"JSON report has unexpected schema: {payload.get('schema')!r}")
    elif report_format == "sarif":
        payload = json.loads(response.body.decode("utf-8"))
        _assert_no_private_paths(payload)
        if payload.get("version") != "2.1.0" or not isinstance(payload.get("runs"), list):
            raise RuntimeError("SARIF report does not contain version=2.1.0 and runs[].")
    elif report_format == "zip":
        if not response.body.startswith(b"PK"):
            raise RuntimeError("Evidence ZIP download does not start with a ZIP file header.")
        verification = _request(
            f"{BASE_URL}/reports/{report_id}/verify",
            data=b"",
            headers={"Content-Type": "application/json"},
        )
        _assert_no_private_paths(verification)
        summary = verification.get("summary")
        if not isinstance(summary, dict) or summary.get("ok") is not True:
            raise RuntimeError(f"Evidence ZIP verification failed: {verification!r}")
    else:
        _assert_no_private_paths(response.body.decode("utf-8", errors="replace"))


def _trigger_provider_update() -> dict[str, object]:
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
        headers={"Content-Type": "application/json"},
    )


def _get_provider_status() -> dict[str, object]:
    return _request(f"{BASE_URL}/providers/status")


def _request(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    response = _raw_request(url, data=data, headers=headers)
    return json.loads(response.body.decode("utf-8"))


@dataclass(frozen=True)
class RawResponse:
    """Raw HTTP response returned by the quickstart smoke helper."""

    body: bytes
    headers: object
    status: int


def _raw_request(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> RawResponse:
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return RawResponse(
                body=response.read(),
                headers=response.headers,
                status=response.status,
            )
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


def _assert_download_response(response: RawResponse, *, report: dict[str, object]) -> None:
    if not response.body:
        raise RuntimeError(f"Report {report.get('id')} download returned an empty body.")
    content_disposition = response.headers.get("Content-Disposition", "")
    if "attachment" not in content_disposition.lower():
        raise RuntimeError(f"Report download is not an attachment: {content_disposition!r}")
    filename = str(report.get("filename") or "")
    if filename and filename not in content_disposition:
        raise RuntimeError(
            f"Report download disposition does not contain filename {filename!r}: "
            f"{content_disposition!r}"
        )
    _assert_no_private_paths(content_disposition)
    _assert_no_private_paths(response.body.decode("utf-8", errors="replace"))


def _assert_no_private_paths(payload: object) -> None:
    serialized = json.dumps(payload, sort_keys=True) if not isinstance(payload, str) else payload
    if PRIVATE_PATH_PATTERN.search(serialized):
        raise RuntimeError(f"Response leaked a private path: {serialized[:500]}")


def _assert_no_raw_workflow_fields(payload: dict[str, object]) -> None:
    raw_fields = {"summary_json", "error_json"} & payload.keys()
    if raw_fields:
        raise RuntimeError(f"Normal API response exposed raw workflow fields: {sorted(raw_fields)}")


if __name__ == "__main__":
    main()
