"""Production-like Docker smoke for the public Workbench deployment contract."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookies import SimpleCookie
from pathlib import Path
from uuid import uuid4

BASE_URL = os.environ.get("VPW_PRODUCTION_SMOKE_BASE_URL", "http://127.0.0.1:5180")
HOST = os.environ.get("VPW_PRODUCTION_SMOKE_HOST", "workbench.example.test")
USERNAME = os.environ.get("VPW_PRODUCTION_SMOKE_USERNAME", "admin@example.com")
PASSWORD = os.environ.get("VPW_PRODUCTION_SMOKE_PASSWORD", "production-smoke-admin-password")
REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CVES = REPO_ROOT / "data" / "sample_cves.txt"
PRIVATE_PATH_PATTERN = re.compile(
    r"(/Users/|/private/|/tmp/|/app/template-|[A-Za-z]:\\\\)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LoginSession:
    token: str
    csrf_token: str
    cookie_header: str


def main() -> None:
    _assert_frontend_headers()
    _assert_public_health_and_gated_diagnostics()
    login = _login()
    _assert_cookie_csrf(login)
    status = _json("/api/v1/workbench/status", token=login.token)
    _assert_ready_status(status)
    project_id = _create_project(login.token)
    run = _import_demo(login.token, project_id)
    findings = _get_findings(login.token, project_id)
    report = _create_report(login.token, str(run["id"]))
    _download_report(login.token, str(report["id"]))
    _logout_and_assert_revoked(login.token)

    print(
        "Production-like smoke passed: "
        f"project_id={project_id} run_id={run['id']} findings={len(findings)} "
        f"report_id={report['id']} host={HOST}"
    )


def _assert_frontend_headers() -> None:
    response = _raw("/", expected_status=200)
    csp = response.headers.get("Content-Security-Policy", "")
    if "connect-src 'self'" not in csp:
        raise RuntimeError(f"Frontend CSP does not enforce same-origin API calls: {csp!r}")
    for forbidden in ("localhost:8000", "127.0.0.1:8000", "api.workbench.example.test"):
        if forbidden in csp:
            raise RuntimeError(f"Frontend CSP leaks a forbidden API origin: {forbidden}")


def _assert_public_health_and_gated_diagnostics() -> None:
    health = _json("/api/v1/workbench/health")
    if health != {"status": "ok"}:
        raise RuntimeError(f"Unexpected public health payload: {health!r}")
    _raw("/api/v1/workbench/status", expected_status=401)
    _raw("/api/v1/providers/status", expected_status=401)
    _raw("/docs", expected_status=404)
    _raw("/api/v1/openapi.json", expected_status=404)


def _login() -> LoginSession:
    payload = urllib.parse.urlencode({"username": USERNAME, "password": PASSWORD}).encode()
    response = _raw(
        "/api/v1/login/access-token",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    body = json.loads(response.body.decode("utf-8"))
    _assert_no_private_paths(body)
    token = str(body["access_token"])
    cookies = _response_cookies(response)
    cookie_header = _cookie_header(cookies)
    session_cookie = cookies.get("vpw_session")
    csrf_cookie = cookies.get("vpw_csrf")
    if not session_cookie or not csrf_cookie:
        raise RuntimeError("Login did not set vpw_session and vpw_csrf cookies.")
    for cookie_name in ("vpw_session", "vpw_csrf"):
        raw_cookie = response.cookies[cookie_name]
        if "secure" not in raw_cookie.lower() or "samesite=lax" not in raw_cookie.lower():
            raise RuntimeError(f"{cookie_name} cookie is not production hardened: {raw_cookie!r}")
    if "httponly" not in response.cookies["vpw_session"].lower():
        raise RuntimeError("vpw_session cookie is not HttpOnly.")
    if "httponly" in response.cookies["vpw_csrf"].lower():
        raise RuntimeError("vpw_csrf cookie must be readable for CSRF header submission.")
    return LoginSession(token=token, csrf_token=csrf_cookie, cookie_header=cookie_header)


def _assert_cookie_csrf(login: LoginSession) -> None:
    payload = json.dumps(
        {
            "name": f"csrf-negative-{uuid4().hex[:8]}",
            "description": "CSRF negative smoke",
        }
    ).encode()
    _raw(
        "/api/v1/projects/",
        data=payload,
        expected_status=403,
        headers={
            "Content-Type": "application/json",
            "Cookie": login.cookie_header,
        },
    )
    response = _json(
        "/api/v1/projects/",
        data=json.dumps(
            {
                "name": f"csrf-positive-{uuid4().hex[:8]}",
                "description": "CSRF positive smoke",
            }
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Cookie": login.cookie_header,
            "X-CSRF-Token": login.csrf_token,
        },
    )
    _assert_no_private_paths(response)


def _assert_ready_status(status: dict[str, object]) -> None:
    _assert_no_private_paths(status)
    if status.get("database_status") != "ready" or status.get("schema_status") != "ready":
        raise RuntimeError(f"Production readiness status is not ready: {status!r}")


def _create_project(token: str) -> str:
    response = _json(
        "/api/v1/projects/",
        data=json.dumps(
            {
                "name": f"production-smoke-{uuid4().hex[:8]}",
                "description": "Production-like Docker smoke",
            }
        ).encode(),
        token=token,
        headers={"Content-Type": "application/json"},
    )
    _assert_no_private_paths(response)
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
        files={"file": SAMPLE_CVES},
    )
    response = _json(
        f"/api/v1/projects/{project_id}/imports",
        data=body,
        token=token,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    _assert_no_private_paths(response)
    if response.get("status") not in {"succeeded", "completed"}:
        raise RuntimeError(f"Import did not complete successfully: {response!r}")
    return response


def _get_findings(token: str, project_id: str) -> list[dict[str, object]]:
    response = _json(f"/api/v1/projects/{project_id}/findings/?sort=cve", token=token)
    _assert_no_private_paths(response)
    findings = response.get("data")
    if not isinstance(findings, list) or not findings:
        raise RuntimeError("Production smoke import produced no findings.")
    return findings


def _create_report(token: str, run_id: str) -> dict[str, object]:
    response = _json(
        f"/api/v1/runs/{run_id}/reports",
        data=json.dumps({"format": "markdown"}).encode(),
        token=token,
        headers={"Content-Type": "application/json"},
    )
    _assert_no_private_paths(response)
    return response


def _download_report(token: str, report_id: str) -> None:
    response = _raw(f"/api/v1/reports/{report_id}/download", token=token)
    if not response.body:
        raise RuntimeError("Report download returned an empty body.")
    content_disposition = response.headers.get("Content-Disposition", "")
    if "attachment" not in content_disposition.lower():
        raise RuntimeError(f"Report download is not an attachment: {content_disposition!r}")


def _logout_and_assert_revoked(token: str) -> None:
    _json("/api/v1/login/logout", data=b"", token=token)
    _raw("/api/v1/users/me", token=token, expected_status=403)


@dataclass(frozen=True)
class RawResponse:
    body: bytes
    cookies: dict[str, str]
    headers: object
    status: int


def _json(
    path: str,
    *,
    data: bytes | None = None,
    token: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    response = _raw(path, data=data, token=token, headers=headers)
    return json.loads(response.body.decode("utf-8"))


def _raw(
    path: str,
    *,
    data: bytes | None = None,
    token: str | None = None,
    headers: dict[str, str] | None = None,
    expected_status: int = 200,
) -> RawResponse:
    request_headers = {"Host": HOST, **(headers or {})}
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
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


def _response_cookies(response: RawResponse) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_value in response.cookies.values():
        parsed = SimpleCookie()
        parsed.load(raw_value)
        for name, morsel in parsed.items():
            values[name] = morsel.value
    return values


def _cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


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
    serialized = json.dumps(payload, sort_keys=True)
    if PRIVATE_PATH_PATTERN.search(serialized):
        raise RuntimeError(f"Response leaked a private path: {serialized[:500]}")


if __name__ == "__main__":
    main()
