"""Production-like Docker smoke for the public Workbench deployment contract."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.cookies import SimpleCookie
from pathlib import Path
from uuid import uuid4

BASE_URL = os.environ.get("VPW_PRODUCTION_SMOKE_BASE_URL", "http://127.0.0.1:5180")
HOST = os.environ.get("VPW_PRODUCTION_SMOKE_HOST", "workbench.example.test")
REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CVES = REPO_ROOT / "data" / "sample_cves.txt"
PRIVATE_PATH_PATTERN = re.compile(
    r"(/Users/|/private/|/tmp/|/app/(?:template|workbench)-|[A-Za-z]:\\\\)",
    re.IGNORECASE,
)
IMPORT_SUCCESS_STATUSES = {"completed", "succeeded"}
IMPORT_FAILURE_STATUSES = {"failed"}
IMPORT_POLL_SECONDS = int(os.environ.get("VPW_PRODUCTION_SMOKE_IMPORT_TIMEOUT", "60"))
REPORT_FORMATS = ("markdown", "html", "json", "csv", "sarif", "zip")


def main() -> None:
    """Exercise the production-like Workbench deployment smoke path."""
    _assert_frontend_headers()
    _assert_public_health_and_status()
    status = _json("/api/v1/workbench/status")
    _assert_ready_status(status)
    project_id = _create_project()
    run = _import_demo(project_id)
    findings = _get_findings(project_id)
    reports = _create_reports(str(run["id"]))
    for report_format, report in reports.items():
        _download_report(report_format=report_format, report=report)

    print(
        "Production-like smoke passed: "
        f"project_id={project_id} run_id={run['id']} findings={len(findings)} "
        f"reports={','.join(reports)} host={HOST}"
    )


def _assert_frontend_headers() -> None:
    response = _raw("/", expected_status=200)
    csp = response.headers.get("Content-Security-Policy", "")
    if "connect-src 'self'" not in csp:
        raise RuntimeError(f"Frontend CSP does not enforce same-origin API calls: {csp!r}")
    for forbidden in ("localhost:8000", "127.0.0.1:8000", "api.workbench.example.test"):
        if forbidden in csp:
            raise RuntimeError(f"Frontend CSP leaks a forbidden API origin: {forbidden}")


def _assert_public_health_and_status() -> None:
    health = _json("/api/v1/workbench/health")
    if health != {"status": "ok"}:
        raise RuntimeError(f"Unexpected public health payload: {health!r}")
    _assert_ready_status(_json("/api/v1/workbench/status"))
    _assert_no_private_paths(_json("/api/v1/providers/status"))
    _raw("/docs", expected_status=404)
    _raw("/api/v1/openapi.json", expected_status=404)


def _assert_ready_status(status: dict[str, object]) -> None:
    _assert_no_private_paths(status)
    if status.get("database_status") != "ready" or status.get("schema_status") != "ready":
        raise RuntimeError(f"Production readiness status is not ready: {status!r}")


def _create_project() -> str:
    response = _json(
        "/api/v1/projects/",
        data=json.dumps(
            {
                "name": f"production-smoke-{uuid4().hex[:8]}",
                "description": "Production-like Docker smoke",
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    _assert_no_private_paths(response)
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
        files={"file": SAMPLE_CVES},
    )
    response = _json(
        f"/api/v1/projects/{project_id}/imports",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    _assert_no_private_paths(response)
    if response.get("status") in IMPORT_SUCCESS_STATUSES:
        return response
    return _wait_for_import_completion(response)


def _wait_for_import_completion(initial_response: dict[str, object]) -> dict[str, object]:
    run_id = str(initial_response.get("id") or "")
    if not run_id:
        raise RuntimeError(f"Import response did not include a run id: {initial_response!r}")

    deadline = time.monotonic() + IMPORT_POLL_SECONDS
    last_response = initial_response
    while time.monotonic() < deadline:
        if last_response.get("status") in IMPORT_FAILURE_STATUSES:
            raise RuntimeError(f"Import failed: {last_response!r}")
        if last_response.get("status") in IMPORT_SUCCESS_STATUSES:
            return last_response
        time.sleep(1)
        last_response = _json(f"/api/v1/runs/{run_id}")
        _assert_no_private_paths(last_response)

    raise RuntimeError(f"Import did not complete within {IMPORT_POLL_SECONDS}s: {last_response!r}")


def _get_findings(project_id: str) -> list[dict[str, object]]:
    response = _json(f"/api/v1/projects/{project_id}/findings/?sort=cve")
    _assert_no_private_paths(response)
    findings = response.get("data")
    if not isinstance(findings, list) or not findings:
        raise RuntimeError("Production smoke import produced no findings.")
    return findings


def _create_reports(run_id: str) -> dict[str, dict[str, object]]:
    reports: dict[str, dict[str, object]] = {}
    for report_format in REPORT_FORMATS:
        response = _json(
            f"/api/v1/runs/{run_id}/reports",
            data=json.dumps({"format": report_format}).encode(),
            headers={"Content-Type": "application/json"},
        )
        _assert_no_private_paths(response)
        reports[report_format] = response
    return reports


def _download_report(*, report_format: str, report: dict[str, object]) -> None:
    report_id = str(report["id"])
    response = _raw(f"/api/v1/reports/{report_id}/download")
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
        verification = _json(
            f"/api/v1/reports/{report_id}/verify",
            data=b"",
            headers={"Content-Type": "application/json"},
        )
        _assert_no_private_paths(verification)
        summary = verification.get("summary")
        if not isinstance(summary, dict) or summary.get("ok") is not True:
            raise RuntimeError(f"Evidence ZIP verification failed: {verification!r}")
    else:
        _assert_no_private_paths(response.body.decode("utf-8", errors="replace"))


@dataclass(frozen=True)
class RawResponse:
    """Raw HTTP response returned by the production smoke helper."""

    body: bytes
    cookies: dict[str, str]
    headers: object
    status: int


def _json(
    path: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    response = _raw(path, data=data, headers=headers)
    return json.loads(response.body.decode("utf-8"))


def _raw(
    path: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    expected_status: int = 200,
) -> RawResponse:
    request_headers = {"Host": HOST, **(headers or {})}
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers=request_headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            if response.status != expected_status:
                raise RuntimeError(
                    f"{path} returned HTTP {response.status}, expected {expected_status}: "
                    f"{body.decode('utf-8', errors='replace')}"
                )
            return RawResponse(
                body=body,
                cookies=_raw_set_cookie_headers(response.headers),
                headers=response.headers,
                status=response.status,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read()
        if exc.code == expected_status:
            return RawResponse(
                body=body,
                cookies=_raw_set_cookie_headers(exc.headers),
                headers=exc.headers,
                status=exc.code,
            )
        raise RuntimeError(
            f"{path} failed with HTTP {exc.code}, expected {expected_status}: "
            f"{body.decode('utf-8', errors='replace')}"
        ) from exc


def _raw_set_cookie_headers(headers: object) -> dict[str, str]:
    get_all = getattr(headers, "get_all", None)
    raw_values = get_all("Set-Cookie") if callable(get_all) else []
    cookies: dict[str, str] = {}
    for raw_value in raw_values or []:
        parsed = SimpleCookie()
        parsed.load(raw_value)
        for name, morsel in parsed.items():
            cookies[name] = raw_value
    return cookies


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
    return b"".join(parts)


def _assert_no_private_paths(payload: object) -> None:
    serialized = json.dumps(payload, sort_keys=True) if not isinstance(payload, str) else payload
    if PRIVATE_PATH_PATTERN.search(serialized):
        raise RuntimeError(f"Response leaked a private path: {serialized[:500]}")


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


if __name__ == "__main__":
    main()
