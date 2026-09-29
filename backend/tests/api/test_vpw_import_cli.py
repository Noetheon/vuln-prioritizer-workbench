"""`vpw import` uploads through the Workbench API and reports the finished run."""

from __future__ import annotations

import json
import os
import urllib.parse
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest
from utils.demo_imports import GENERIC_CSV_HEADER, configure_demo_imports
from utils.import_contracts import drain_workflow_queue
from utils.workbench_env import WorkbenchApiEnv

from app.cli import main
from app.services import api_import_client
from app.services.api_import_client import HttpResponse, WorkbenchImportClient


@pytest.fixture(autouse=True)
def _restore_process_environment() -> Iterator[None]:
    original = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def _app_transport(env: WorkbenchApiEnv, calls: list[str]):
    def send(method: str, url: str, body: bytes | None, headers: Mapping[str, str]) -> HttpResponse:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        calls.append(f"{method} {parsed.path}")
        if parsed.path.startswith("/api/v1/runs/"):
            drain_workflow_queue(env)
        response = env.client.request(method, path, content=body, headers=dict(headers))
        return HttpResponse(status=response.status_code, body=response.content)

    return send


def _scan(tmp_path: Path, name: str, rows: list[str]) -> Path:
    path = tmp_path / name
    path.write_bytes(GENERIC_CSV_HEADER + "".join(rows).encode())
    return path


def test_vpw_import_creates_the_project_uploads_and_waits(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    env = workbench_api_env
    configure_demo_imports(env, tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        api_import_client, "urllib_transport", lambda *args, **kwargs: _app_transport(env, calls)
    )
    common = [
        "--project",
        "CLI project",
        "--input-type",
        "generic-occurrence-csv",
        "--provider-snapshot",
        "demo.json",
        "--locked-provider-data",
        "--url",
        "http://127.0.0.1:8765/",
    ]
    first = _scan(
        tmp_path,
        "first.csv",
        ["CVE-2021-44228,web-1,log4j-core,2.14.1\n", "CVE-2022-22965,web-1,spring-beans,5.3.17\n"],
    )

    with pytest.raises(SystemExit, match="No project named 'CLI project'"):
        main(["import", str(first), *common])
    assert main(["import", str(first), *common, "--create-project"]) == 0
    output = capsys.readouterr().out
    assert "Imported first.csv into CLI project" in output
    assert "succeeded" in output
    assert "Findings: 2 created, 0 updated, 0 resolved, 0 reopened" in output
    assert "http://127.0.0.1:8765/imports/runs/" in output
    assert "POST /api/v1/projects/" in calls

    rescan = _scan(tmp_path, "rescan.csv", ["CVE-2021-44228,web-1,log4j-core,2.14.1\n"])
    assert main(["import", str(rescan), *common, "--keep-missing-open", "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "succeeded"
    assert summary["resolved_findings"] == 0
    assert main(["import", str(rescan), *common]) == 0
    assert "1 resolved" in capsys.readouterr().out

    assert main(["import", str(rescan), *common, "--no-wait"]) == 0
    assert "Queued run" in capsys.readouterr().out

    with pytest.raises(SystemExit, match="HTTP 4"):
        main(["import", str(rescan), *[*common[:3], "not-a-format", *common[4:]]])
    with pytest.raises(SystemExit, match="Import file not found"):
        main(["import", str(tmp_path / "missing.csv"), *common])


def test_import_client_reports_unreachable_workbench_and_timeouts(tmp_path: Path) -> None:
    unreachable = WorkbenchImportClient(
        "http://127.0.0.1:9",
        api_import_client.urllib_transport(timeout_seconds=2.0),
    )
    with pytest.raises(api_import_client.ImportClientError, match="Cannot reach the Workbench"):
        unreachable.resolve_project("any")

    def pending(
        method: str, url: str, body: bytes | None, headers: Mapping[str, str]
    ) -> HttpResponse:
        return HttpResponse(status=200, body=b'{"id": "run-1", "status": "running"}')

    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    client = WorkbenchImportClient("http://workbench", pending)
    with pytest.raises(api_import_client.ImportClientError, match="still running after 3s"):
        client.wait_for_run("run-1", timeout_seconds=3, sleep=sleep, clock=lambda: now[0])

    def duplicates(
        method: str, url: str, body: bytes | None, headers: Mapping[str, str]
    ) -> HttpResponse:
        projects = [{"id": "a", "name": "Same"}, {"id": "b", "name": "Same"}]
        return HttpResponse(status=200, body=json.dumps({"data": projects}).encode())

    with pytest.raises(api_import_client.ImportClientError, match="pass the project id"):
        WorkbenchImportClient("http://workbench", duplicates).resolve_project("Same")
    assert WorkbenchImportClient("http://workbench", duplicates).resolve_project("b")["id"] == "b"


def test_import_client_sends_extra_headers_for_login_proxies() -> None:
    seen: list[Mapping[str, str]] = []

    def capture(
        method: str, url: str, body: bytes | None, headers: Mapping[str, str]
    ) -> HttpResponse:
        seen.append(dict(headers))
        return HttpResponse(status=200, body=b'{"data": [{"id": "p1", "name": "Team"}]}')

    client = WorkbenchImportClient(
        "http://workbench",
        capture,
        extra_headers=dict([api_import_client.parse_header_option("Authorization: Bearer t0k")]),
    )
    assert client.resolve_project("Team")["id"] == "p1"
    assert seen[-1]["Authorization"] == "Bearer t0k"
    assert seen[-1]["Accept"] == "application/json"

    assert api_import_client.parse_header_option(" X-Team :  a:b ") == ("X-Team", "a:b")
    for invalid in ("no-colon", "Bad Name: x", ": x", "X-Team: a\r\nX-Evil: 1"):
        with pytest.raises(api_import_client.ImportClientError):
            api_import_client.parse_header_option(invalid)
    with pytest.raises(SystemExit, match="Headers must look like"):
        main(["import", __file__, "--project", "p", "--input-type", "cve-list", "--header", "x"])
