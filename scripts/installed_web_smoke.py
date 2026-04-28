#!/usr/bin/env python3
"""Smoke-test an installed Workbench web server and packaged React assets."""

from __future__ import annotations

import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


def main() -> int:
    host = "127.0.0.1"
    port = _free_port()
    base_url = f"http://{host}:{port}"
    binary = os.environ.get("VULN_PRIORITIZER_BIN", "vuln-prioritizer")

    with tempfile.TemporaryDirectory(prefix="vpr-web-smoke-") as tmp:
        tmp_path = Path(tmp)
        env = os.environ.copy()
        env.update(
            {
                "VULN_PRIORITIZER_DB_URL": f"sqlite:///{tmp_path / 'workbench.db'}",
                "VULN_PRIORITIZER_UPLOAD_DIR": str(tmp_path / "uploads"),
                "VULN_PRIORITIZER_REPORT_DIR": str(tmp_path / "reports"),
                "VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR": str(tmp_path / "provider-snapshots"),
                "VULN_PRIORITIZER_CACHE_DIR": str(tmp_path / "cache"),
            }
        )
        process = subprocess.Popen(
            [binary, "web", "serve", "--host", host, "--port", str(port)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            _wait_for_health(base_url, process)
            root_url = urllib.request.urlopen(base_url + "/", timeout=5).geturl()
            html = urllib.request.urlopen(base_url + "/app", timeout=5).read().decode()
            deep_html = (
                urllib.request.urlopen(base_url + "/app/projects/demo/dashboard", timeout=5)
                .read()
                .decode()
            )
            assets = set(re.findall(r'/static/app/assets/[^"<> ]+', html))
            assert root_url.endswith("/app"), "Root did not redirect to /app."
            assert assets, "React Workbench did not reference packaged assets."
            assert html == deep_html, "Deep SPA fallback did not serve the React entry."
            for asset in assets:
                urllib.request.urlopen(base_url + asset, timeout=5).read(1)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
    print("Installed Workbench web smoke passed.")
    return 0


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_health(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError(f"Workbench server exited early.\n{output}")
        try:
            urllib.request.urlopen(base_url + "/healthz", timeout=2).read()
            return
        except Exception:
            time.sleep(1)
    output = process.stdout.read() if process.stdout is not None else ""
    raise TimeoutError(f"Workbench health check timed out.\n{output}")


if __name__ == "__main__":
    raise SystemExit(main())
