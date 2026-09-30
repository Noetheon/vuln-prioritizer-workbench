"""Run pinned Grype with an isolated database through the actual API and worker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import requests
from filelock import FileLock

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    """Hash an artifact without loading the database into memory."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def scanner_pin() -> dict:
    """Keep the native contract runner aligned with the Docker scanner pin."""
    pin = json.loads((ROOT / "scripts/grype-checksums.json").read_text())
    docker = (ROOT / "docker/security-tools/Dockerfile").read_text()
    version = re.search(r"anchore/grype:v([0-9.]+)@sha256:[0-9a-f]{64}", docker)
    if not version or version[1] != pin["version"]:
        raise ValueError("Review native Grype checksums when updating the Docker scanner pin.")
    return pin


def download_binary(destination: Path, pin: dict) -> Path:
    """Extract only the executable from an archive with a committed checksum."""
    machine = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    target = f"{platform.system().lower()}_{machine}"
    expected = pin["archives"].get(target)
    if not expected:
        raise ValueError(f"Unsupported scanner platform: {target}")
    version = pin["version"]
    url = f"https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_{target}.tar.gz"
    archive = destination / "grype.tar.gz"
    deadline = time.monotonic() + 120
    with requests.get(url, stream=True, timeout=(20, 60)) as response:
        response.raise_for_status()
        with archive.open("wb") as output:
            for chunk in response.iter_content(1024 * 1024):
                if time.monotonic() > deadline:
                    raise ValueError("Scanner archive download exceeds its time budget")
                output.write(chunk)
                if output.tell() > 200 * 1024 * 1024:
                    raise ValueError("Scanner archive exceeds the 200 MiB setup budget")
    if sha256(archive) != expected:
        raise ValueError("Grype archive checksum mismatch")
    binary = destination / "grype"
    with tarfile.open(archive) as bundle:
        member = bundle.getmember("grype")
        if not member.isfile():
            raise ValueError("Scanner archive must contain a regular executable")
        stream = bundle.extractfile(member)
        if stream is None:
            raise ValueError("Scanner executable missing")
        with stream, binary.open("wb") as output:
            shutil.copyfileobj(stream, output)
    binary.chmod(0o700)
    return binary


def main() -> int:
    """Retain provenance and logs on success and on setup or contract failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db-archive", type=Path, help="Import a retained DB archive instead of updating"
    )
    parser.add_argument("--db-sha256", help="Required checksum for --db-archive")
    args = parser.parse_args()
    if bool(args.db_archive) != bool(args.db_sha256):
        parser.error("--db-archive and --db-sha256 must be supplied together")
    output = ROOT / "build/grype-integration"
    output.mkdir(parents=True, exist_ok=True)
    evidence: dict = {
        "schema": "vpw.grype-integration.v1",
        "status": "failed",
        "python": sys.version,
    }
    started = time.monotonic()
    acquired = False
    try:
        with (
            FileLock(str(output / ".lock"), timeout=0),
            tempfile.TemporaryDirectory(prefix="scanner-", dir=output) as scratch,
        ):
            acquired = True
            for stale in ("setup.log", "tests.log", "junit.xml"):
                (output / stale).unlink(missing_ok=True)
            if (output / "contracts").exists():
                shutil.rmtree(output / "contracts")
            root = Path(scratch)
            pin = scanner_pin()
            evidence["pin"] = pin
            evidence["commit"] = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip()
            binary = download_binary(root, pin)
            evidence["binary_sha256"] = sha256(binary)
            evidence["test_sha256"] = sha256(ROOT / "backend/tests/live/test_sbom_live_contract.py")
            env = {
                **os.environ,
                "GRYPE_DB_CACHE_DIR": str(root / "db"),
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                "GRYPE_DB_AUTO_UPDATE": "false",
            }
            with (output / "setup.log").open("w") as log:
                if args.db_archive:
                    if sha256(args.db_archive) != args.db_sha256:
                        raise ValueError("Provided DB archive checksum mismatch")
                    evidence["database_archive_sha256"] = args.db_sha256
                    command = [str(binary), "db", "import", str(args.db_archive.resolve())]
                else:
                    command = [str(binary), "db", "update"]
                subprocess.run(
                    command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600, check=True
                )
            evidence["scanner"] = json.loads(
                subprocess.check_output([str(binary), "version", "-o", "json"], env=env, timeout=30)
            )
            evidence["database"] = json.loads(
                subprocess.check_output(
                    [str(binary), "db", "status", "-o", "json"], env=env, timeout=30
                )
            )
            if (
                evidence["scanner"].get("version") != pin["version"]
                or evidence["database"].get("valid") is not True
            ):
                raise ValueError(
                    "Scanner version or database validity differs from the expected setup"
                )
            evidence["database_files_sha256"] = {
                str(path.relative_to(root / "db")): sha256(path)
                for path in (root / "db").rglob("*.db")
            }
            if not evidence["database_files_sha256"]:
                raise ValueError("No verified Grype database file found")
            env.update(
                VPW_TEST_GRYPE_BINARY=str(binary),
                VPW_TEST_GRYPE_DB=str(root / "db"),
                VPW_SBOM_VALIDATION_OUTPUT=str(output / "contracts"),
                VPW_TEST_GRYPE_VERSION=pin["version"],
                VPW_TEST_GRYPE_DB_SHA256=json.dumps(
                    list(evidence["database_files_sha256"].values())
                ),
            )
            with (output / "tests.log").open("w") as log:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        "-q",
                        "--no-cov",
                        "--junitxml=build/grype-integration/junit.xml",
                        "backend/tests/live/test_sbom_live_contract.py",
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=600,
                )
            evidence["test_exit_code"] = result.returncode
            if result.returncode:
                raise RuntimeError("Real Grype contract failed; inspect tests.log")
            cases = ET.parse(output / "junit.xml").findall(".//testcase")
            if len(cases) != 3 or any(case.find("skipped") is not None for case in cases):
                raise RuntimeError("The scanner gate requires all three contracts without skips")
            evidence["executed_contracts"] = len(cases)
            evidence["status"] = "passed"
    except (
        OSError,
        ValueError,
        RuntimeError,
        requests.RequestException,
        subprocess.SubprocessError,
    ) as exc:
        evidence["error"] = str(exc)
        print(f"Grype integration failed: {exc}", file=sys.stderr)
    finally:
        evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if acquired:
            (output / "provenance.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Real Grype contract {evidence['status']}; evidence: {output}")
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
