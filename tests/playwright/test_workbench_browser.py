from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
DEMO_PROVIDER_SNAPSHOT = ROOT / "data" / "demo_provider_snapshot.json"
TRIVY_REPORT = ROOT / "data" / "input_fixtures" / "trivy_report.json"
SAMPLE_CVES = ROOT / "data" / "sample_cves.txt"
ASSET_CONTEXT = ROOT / "data" / "input_fixtures" / "example_asset_context.csv"
OPENVEX = ROOT / "data" / "input_fixtures" / "openvex_statements.json"
ATTACK_MAPPING = (
    ROOT / "data" / "attack" / ("ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json")
)
ATTACK_METADATA = ROOT / "data" / "attack" / "attack_techniques_enterprise_16.1_subset.json"
RUN_PLAYWRIGHT = os.getenv("VULN_PRIORITIZER_RUN_PLAYWRIGHT") == "1"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.browser_e2e,
    pytest.mark.skipif(
        not RUN_PLAYWRIGHT,
        reason="Set VULN_PRIORITIZER_RUN_PLAYWRIGHT=1 or run `make playwright-check`.",
    ),
]


@dataclass(frozen=True)
class LiveWorkbench:
    base_url: str
    tmp_path: Path


@pytest.fixture
def live_workbench(tmp_path: Path) -> Iterator[LiveWorkbench]:
    port = _pick_free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["VULN_PRIORITIZER_DB_URL"] = f"sqlite:///{tmp_path / 'workbench.db'}"
    env["VULN_PRIORITIZER_UPLOAD_DIR"] = str(tmp_path / "uploads")
    env["VULN_PRIORITIZER_REPORT_DIR"] = str(tmp_path / "reports")
    env["VULN_PRIORITIZER_CACHE_DIR"] = str(tmp_path / "cache")
    env["VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR"] = str(ROOT / "data")
    env["VULN_PRIORITIZER_ATTACK_ARTIFACT_DIR"] = str(ROOT / "data" / "attack")
    env["VULN_PRIORITIZER_CSRF_TOKEN"] = "playwright-csrf-token"
    env["VULN_PRIORITIZER_FIXED_NOW"] = "2026-04-21T12:00:00+00:00"
    env["VULN_PRIORITIZER_ALLOWED_HOSTS"] = "127.0.0.1,localhost,testserver"
    env["NVD_API_KEY"] = "secret-api-key"

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "vuln_prioritizer.cli",
            "web",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_health(base_url, process)
        yield LiveWorkbench(base_url=base_url, tmp_path=tmp_path)
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)


@pytest.fixture
def browser() -> Iterator[Any]:
    sync_api = pytest.importorskip(
        "playwright.sync_api",
        reason="Install the dev extra and run `python3 -m playwright install chromium`.",
    )
    try:
        with sync_api.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                yield browser
            finally:
                browser.close()
    except sync_api.Error as exc:
        if "Executable doesn't exist" in str(exc):
            pytest.fail("Chromium is missing. Run `python3 -m playwright install chromium`.")
        raise


def test_workbench_browser_happy_path_reports_and_responsive_pages(
    live_workbench: LiveWorkbench,
    browser: Any,
) -> None:
    context = browser.new_context(accept_downloads=True, viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    browser_errors = _attach_browser_error_log(page)
    waiver_file = _write_waiver_file(live_workbench.tmp_path)

    page.goto(f"{live_workbench.base_url}/", wait_until="networkidle")
    page.wait_for_url(re.compile(r".*/projects/new"))
    _assert_usable_layout(page)

    page.get_by_label("Project name").fill("playwright-workbench")
    page.get_by_label("Description").fill("Real browser coverage")
    with page.expect_navigation(wait_until="networkidle"):
        page.get_by_role("button", name="Create project").click()
    project_id = _project_id_from_url(page.url)
    _assert_usable_layout(page)

    page.get_by_role("link", name="Import findings").click()
    page.wait_for_url(re.compile(r".*/imports/new"))
    page.select_option('select[name="input_format"]', "trivy-json")
    page.set_input_files('input[name="files"]', str(TRIVY_REPORT))
    page.get_by_label("Provider snapshot").fill(DEMO_PROVIDER_SNAPSHOT.name)
    page.get_by_label("Locked provider data").check()
    page.select_option('select[name="attack_source"]', "ctid-json")
    page.get_by_label("ATT&CK mapping file").fill(ATTACK_MAPPING.name)
    page.get_by_label("ATT&CK technique metadata").fill(ATTACK_METADATA.name)
    page.set_input_files('input[name="asset_context_file"]', str(ASSET_CONTEXT))
    page.set_input_files('input[name="vex_file"]', str(OPENVEX))
    page.set_input_files('input[name="waiver_file"]', str(waiver_file))
    with page.expect_navigation(wait_until="networkidle", timeout=60_000):
        page.get_by_role("button", name="Start import").click()
    run_id = _run_id_from_url(page.url)
    page.get_by_role("main").get_by_text("Run artifacts").wait_for(timeout=10_000)
    page.get_by_role("heading", name="Reports and evidence").wait_for(timeout=10_000)
    page.locator(".hero-meta").get_by_text("trivy_report.json", exact=True).wait_for(timeout=10_000)
    page.get_by_text("No reports generated.").wait_for()
    _assert_usable_layout(page)

    page.get_by_role("link", name="Dashboard").click()
    page.wait_for_url(re.compile(r".*/dashboard"))
    page.get_by_text("CVE-2023-34362").wait_for()
    page.get_by_text("Top techniques").wait_for()
    page.get_by_text("T1190").wait_for()
    page.get_by_text("VEX suppressed").wait_for()
    page.get_by_text("Waiver review due").wait_for()
    page.get_by_role("navigation").get_by_role("link", name="Run artifacts").wait_for()
    page.get_by_role("navigation").get_by_role("link", name="Executive Report").wait_for()
    _assert_usable_layout(page)

    page.get_by_role("link", name="Governance").click()
    page.wait_for_url(re.compile(r".*/governance"))
    page.get_by_text("Remediation ownership").wait_for()
    page.get_by_text("Service pressure").wait_for()
    page.get_by_text("platform-team").wait_for()
    page.get_by_text("customer-login").wait_for()
    page.locator(".metric", has_text="Review due").get_by_text("1").wait_for()
    page.locator(".metric", has_text="VEX suppressed").get_by_text("1").wait_for()
    _assert_usable_layout(page)

    page.get_by_role("navigation").get_by_role("link", name="Findings", exact=True).click()
    page.wait_for_url(re.compile(r".*/findings"))
    page.get_by_label("Search").fill("CVE-1999-0001")
    page.get_by_role("button", name="Apply").click()
    page.wait_for_url(re.compile(r".*[?&]q=CVE-1999-0001"))
    page.get_by_text("Showing 0-0 of 0 findings.").wait_for()
    _assert_usable_layout(page)

    page.goto(f"{live_workbench.base_url}/projects/{project_id}/findings", wait_until="networkidle")
    page.get_by_label("Search").fill("CVE-2024-3094")
    page.select_option('select[name="priority"]', "Critical")
    page.select_option('select[name="kev"]', "false")
    page.get_by_label("Owner").fill("platform-team")
    page.get_by_label("Service").fill("customer-login")
    page.get_by_role("button", name="Apply").click()
    page.wait_for_url(re.compile(r".*[?&]q=CVE-2024-3094"))
    page.get_by_text("Showing 1-1 of 1 findings.").wait_for()
    page.get_by_role("link", name="CVE-2024-3094").click()
    page.get_by_text("Why this priority?").wait_for()
    page.get_by_text("Waiver lifecycle").wait_for()
    page.get_by_text("Ticket: javascript:alert(1)").wait_for()
    assert page.locator('a[href="javascript:alert(1)"]').count() == 0
    _assert_usable_layout(page)

    page.goto(f"{live_workbench.base_url}/projects/{project_id}/vulnerabilities")
    page.get_by_label("CVE ID").fill("CVE-1999-0001")
    page.get_by_role("button", name="Lookup").click()
    page.get_by_text("No stored provider data exists for this CVE").wait_for()
    _assert_usable_layout(page)

    page.get_by_label("CVE ID").fill("CVE-2023-34362")
    page.get_by_role("button", name="Lookup").click()
    page.get_by_text("Stored provider data").wait_for()
    page.get_by_text("CVE-2023-34362").wait_for()
    page.get_by_text("Occurrences in playwright-workbench").wait_for()
    _assert_usable_layout(page)

    page.goto(f"{live_workbench.base_url}/analysis-runs/{run_id}/reports")
    page.get_by_role("link", name="Open executive report").click()
    page.get_by_role("heading", name="Executive Report").wait_for()
    page.get_by_role("heading", name="Executive Security Overview").wait_for()
    page.get_by_role("heading", name="Risk Posture and Source Signals").wait_for()
    page.get_by_role("heading", name="Top ATT&CK-Mapped Findings").wait_for()
    page.get_by_role("heading", name="Next 30 Days").wait_for()
    page.get_by_role("heading", name="Evidence, Data Quality and Methodology").wait_for()
    page.locator(".er-ranked-row").first.click()
    page.locator(".er-live-insight", has_text="CVE-2023-34362").wait_for()
    page.locator(
        '#priority-findings .er-quadrant-scatter .er-dot[data-insight*="CVSS"]'
    ).first.click()
    page.locator(".er-live-insight", has_text="EPSS").wait_for()
    assert page.locator(".er-live-insight").count() == 1
    _assert_usable_layout(page)

    page.goto(f"{live_workbench.base_url}/analysis-runs/{run_id}/reports")
    for report_format in ["json", "markdown", "html", "csv"]:
        with page.expect_navigation(wait_until="networkidle"):
            page.get_by_role("button", name=f"Create {report_format}").click()
        page.locator(".artifact-row", has_text=report_format).first.wait_for()
    expected_suffixes = {
        "json": ".json",
        "markdown": ".md",
        "html": ".html",
        "csv": ".csv",
    }
    for report_format, suffix in expected_suffixes.items():
        with page.expect_download() as report_download:
            page.locator(".artifact-row", has_text=report_format).first.click()
        download = report_download.value
        assert download.suggested_filename.endswith(suffix)
        downloaded_path = download.path()
        assert downloaded_path is not None
        assert Path(downloaded_path).stat().st_size > 0

    with page.expect_navigation(wait_until="networkidle"):
        page.get_by_role("button", name="Create evidence bundle").click()
    page.get_by_role("link", name="Evidence ZIP").wait_for()
    with page.expect_download() as bundle_download:
        page.get_by_role("link", name="Evidence ZIP").click()
    assert bundle_download.value.suggested_filename.endswith(".zip")
    page.get_by_role("link", name="Verify").click()
    page.get_by_role("heading", name="Bundle verification").wait_for()
    page.locator(".metric", has_text="Status").get_by_text("Passed").wait_for()
    _assert_usable_layout(page)

    page.goto(f"{live_workbench.base_url}/projects/{project_id}/settings")
    page.get_by_text("Provider sources").wait_for()
    page.get_by_text("NVD API key value").wait_for()
    assert "secret-api-key" not in page.locator("body").inner_text()
    _assert_usable_layout(page)

    page.get_by_role("link", name="Vuln Prioritizer Workbench").click()
    page.wait_for_url(re.compile(r".*/dashboard"))
    page.get_by_role("heading", name="Security dashboard").wait_for()
    page.locator(".sidebar-project").get_by_text("playwright-workbench", exact=True).wait_for()

    page.set_viewport_size({"width": 390, "height": 844})
    for path in [
        f"/projects/{project_id}/dashboard",
        f"/projects/{project_id}/findings",
        f"/analysis-runs/{run_id}/reports",
        f"/analysis-runs/{run_id}/executive-report",
        f"/projects/{project_id}/settings",
    ]:
        page.goto(f"{live_workbench.base_url}{path}", wait_until="networkidle")
        _assert_usable_layout(page)

    assert browser_errors == []
    context.close()


def test_workbench_browser_error_states_are_visible(
    live_workbench: LiveWorkbench,
    browser: Any,
) -> None:
    context = browser.new_context(viewport={"width": 1280, "height": 900})
    page = context.new_page()
    browser_errors = _attach_browser_error_log(page)

    page.goto(f"{live_workbench.base_url}/projects/new", wait_until="networkidle")
    page.get_by_label("Project name").fill("playwright-errors")
    with page.expect_navigation(wait_until="networkidle"):
        page.get_by_role("button", name="Create project").click()
    project_id = _project_id_from_url(page.url)

    page.goto(f"{live_workbench.base_url}/projects/new", wait_until="networkidle")
    page.get_by_label("Project name").fill("playwright-errors")
    with page.expect_navigation(wait_until="networkidle") as duplicate_navigation:
        page.get_by_role("button", name="Create project").click()
    assert duplicate_navigation.value is not None
    assert duplicate_navigation.value.status == 409
    page.get_by_role("heading", name="409 Conflict").wait_for()
    page.get_by_text("Project already exists.").wait_for()
    _assert_workbench_error_page(page)

    page.goto(
        f"{live_workbench.base_url}/projects/{project_id}/imports/new", wait_until="networkidle"
    )
    page.set_input_files('input[name="files"]', str(SAMPLE_CVES))
    page.get_by_label("Provider snapshot").fill("missing-snapshot.json")
    with page.expect_navigation(wait_until="networkidle") as invalid_import_navigation:
        page.get_by_role("button", name="Start import").click()
    assert invalid_import_navigation.value is not None
    assert invalid_import_navigation.value.status == 422
    page.get_by_role("heading", name="422 Validation error").wait_for()
    page.get_by_text("Provider snapshot file does not exist.").wait_for()
    _assert_workbench_error_page(page)
    page.get_by_role("link", name="Open workspace").click()
    page.wait_for_url(re.compile(r".*/dashboard"))
    page.get_by_role("heading", name="Security dashboard").wait_for()
    page.locator(".sidebar-project").get_by_text("playwright-errors", exact=True).wait_for()

    assert browser_errors == []
    context.close()


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_health(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise AssertionError(f"Workbench exited before health check passed:\n{output}")
        try:
            with urllib.request.urlopen(f"{base_url}/api/health", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
        time.sleep(0.25)
    raise AssertionError(f"Workbench health check timed out: {last_error}")


def _attach_browser_error_log(page: Any) -> list[str]:
    messages: list[str] = []

    def on_console(message: Any) -> None:
        if message.type == "error":
            if re.search(r"server responded with a status of (409|422)", message.text):
                return
            messages.append(f"console error: {message.text}")

    page.on("console", on_console)
    page.on("pageerror", lambda exc: messages.append(f"page error: {exc}"))
    return messages


def _assert_usable_layout(page: Any) -> None:
    page.locator("main.page, .er-shell").first.wait_for()
    overflow = page.evaluate(
        """() => {
            const root = document.documentElement;
            const body = document.body;
            const width = Math.max(root.scrollWidth, body ? body.scrollWidth : 0);
            const offenders = Array.from(document.querySelectorAll("body *"))
                .map((el) => {
                    const rect = el.getBoundingClientRect();
                    return {
                        tag: el.tagName,
                        className: typeof el.className === "string" ? el.className : "",
                        text: (el.textContent || "").trim().slice(0, 60),
                        left: Math.round(rect.left),
                        right: Math.round(rect.right),
                        width: Math.round(rect.width),
                        scrollWidth: el.scrollWidth,
                        clientWidth: el.clientWidth,
                    };
                })
                .filter(
                    (item) =>
                        item.right > window.innerWidth + 1 ||
                        item.scrollWidth > item.clientWidth + 1
                )
                .slice(0, 8);
            return {scrollWidth: width, innerWidth: window.innerWidth, offenders};
        }"""
    )
    assert overflow["scrollWidth"] <= overflow["innerWidth"] + 1, overflow


def _assert_workbench_error_page(page: Any) -> None:
    _assert_usable_layout(page)
    body_text = page.locator("body").inner_text()
    assert "WORKBENCH ERROR" in body_text
    assert "Open workspace" in body_text


def _project_id_from_url(url: str) -> str:
    match = re.search(r"/projects/([^/]+)/dashboard", url)
    assert match is not None, url
    return match.group(1)


def _run_id_from_url(url: str) -> str:
    match = re.search(r"/analysis-runs/([^/]+)/reports", url)
    assert match is not None, url
    return match.group(1)


def _write_waiver_file(tmp_path: Path) -> Path:
    waiver_file = tmp_path / "waivers.yml"
    waiver_file.write_text(
        "\n".join(
            [
                "waivers:",
                "  - id: playwright-xz-review",
                "    cve_id: CVE-2024-3094",
                "    owner: risk-review",
                "    reason: Browser E2E waiver check.",
                "    expires_on: 2099-12-31",
                "    review_on: 2000-01-01",
                '    ticket_url: "javascript:alert(1)"',
                "    services: [customer-login]",
            ]
        ),
        encoding="utf-8",
    )
    return waiver_file
