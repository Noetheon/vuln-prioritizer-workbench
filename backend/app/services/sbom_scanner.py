"""Run the explicitly configured local Grype executable against an SBOM file."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Literal

from filelock import FileLock, Timeout
from packageurl import PackageURL

from app.contracts.sbom import SbomAssessmentV1

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_ENV_ALLOWLIST = frozenset(
    {"PATH", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP", "SSL_CERT_FILE", "SSL_CERT_DIR"}
)


class SbomScannerError(RuntimeError):
    """A scanner prerequisite, input, execution or output validation failed."""


@dataclass(frozen=True)
class SbomInventory:
    """Preflight inventory; identification does not imply scanner coverage."""

    input_format: Literal["cyclonedx-json", "spdx-json"]
    target_ref: str
    component_count: int
    identified_component_count: int
    version_missing_count: int
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class SbomScannerResult:
    """Bounded raw report and the evidence associated with its exact bytes."""

    report: dict[str, Any]
    report_bytes: bytes
    evidence: SbomAssessmentV1


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _json_object(content: bytes, label: str) -> dict[str, Any]:
    try:
        data = json.loads(content)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise SbomScannerError(f"{label} is not valid JSON.") from exc
    if not isinstance(data, dict):
        raise SbomScannerError(f"{label} must be a JSON object.")
    return data


def _components(data: dict[str, Any]) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    if data.get("bomFormat") == "CycloneDX":
        if not re.fullmatch(r"1\.\d+", _text(data.get("specVersion"))):
            raise SbomScannerError("CycloneDX JSON requires a supported 1.x specVersion.")
        pending = data.get("components")
        metadata = data.get("metadata")
        root = metadata.get("component", {}) if isinstance(metadata, dict) else {}
        fmt = "cyclonedx-json"
    elif re.fullmatch(r"SPDX-2\.\d+", _text(data.get("spdxVersion"))):
        pending = data.get("packages")
        described = data.get("documentDescribes", [])
        root = (
            next(
                (p for p in pending or [] if isinstance(p, dict) and p.get("SPDXID") in described),
                {},
            )
            if isinstance(described, list) and isinstance(pending, list)
            else {}
        )
        fmt = "spdx-json"
    else:
        raise SbomScannerError("Only CycloneDX JSON and SPDX 2.x JSON inventories are supported.")
    if not isinstance(pending, list) or not pending:
        raise SbomScannerError("The SBOM must contain a non-empty component/package inventory.")
    result: list[dict[str, Any]] = []
    stack = list(pending)
    while stack:
        component = stack.pop()
        if not isinstance(component, dict) or not _text(component.get("name")):
            raise SbomScannerError("Every SBOM component/package must be an object with a name.")
        result.append(component)
        children = component.get("components", []) if fmt == "cyclonedx-json" else []
        if not isinstance(children, list):
            raise SbomScannerError("Nested CycloneDX components must be an array.")
        stack.extend(children)
    return result, fmt, root if isinstance(root, dict) else {}


def _purl(component: dict[str, Any]) -> PackageURL | None:
    candidate = component.get("purl")
    if not candidate:
        refs = component.get("externalRefs", [])
        if isinstance(refs, list):
            candidate = next(
                (
                    r.get("referenceLocator")
                    for r in refs
                    if isinstance(r, dict) and r.get("referenceType") == "purl"
                ),
                None,
            )
    try:
        return PackageURL.from_string(candidate) if isinstance(candidate, str) else None
    except (ValueError, TypeError):
        return None


def inspect_sbom(content: bytes, *, target_ref: str | None = None) -> SbomInventory:
    """Validate inventory structure and derive identity without temporary file paths."""
    if len(content) > _MAX_INPUT_BYTES:
        raise SbomScannerError("SBOM exceeds the 64 MiB scanner input limit.")
    data = _json_object(content, "SBOM")
    components, fmt, root = _components(data)
    identity = _text(target_ref)
    root_purl = _purl(root)
    if not identity and root_purl:
        identity = root_purl.to_string()
    if not identity and _text(root.get("name")):
        identity = ":".join(filter(None, (_text(root.get("group")), _text(root.get("name")))))
        version = _text(root.get("version") or root.get("versionInfo"))
        if version:
            identity += f"@{version}"
    if not identity:
        # Content identity is stable across upload filenames and repeated assessments.
        identity = "sbom:sha256:" + hashlib.sha256(content).hexdigest()
    if len(identity) > 1024 or any(ord(c) < 32 for c in identity):
        raise SbomScannerError(
            "SBOM target identity must be printable and at most 1024 characters."
        )
    identified = 0
    missing_version = 0
    os_without_distro = 0
    for component in components:
        purl = _purl(component)
        version = _text(component.get("version") or component.get("versionInfo"))
        version = version or (_text(purl.version) if purl else "")
        if not version or version in {"NOASSERTION", "NONE"}:
            missing_version += 1
        elif purl is not None:
            identified += 1
        if purl and purl.type in {"apk", "deb", "rpm"} and not purl.qualifiers.get("distro"):
            os_without_distro += 1
    warnings = []
    if identified < len(components):
        warnings.append(
            f"{len(components) - identified} components lack a valid PURL and version; "
            "matching coverage cannot be established for these components."
        )
    if os_without_distro:
        warnings.append(
            f"{os_without_distro} OS package PURLs lack distro qualifiers; "
            "distribution metadata must be supplied by the SBOM producer."
        )
    return SbomInventory(
        input_format="cyclonedx-json" if fmt == "cyclonedx-json" else "spdx-json",
        target_ref=identity,
        component_count=len(components),
        identified_component_count=identified,
        version_missing_count=missing_version,
        warnings=tuple(warnings),
    )


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        # Descendants may retain the pipes after the immediate child has exited.
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    elif process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=2)
    finally:
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)


def _run_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
    checkpoint: Callable[[], None] | None,
) -> tuple[bytes, bytes]:
    if timeout_seconds <= 0 or max_output_bytes <= 0:
        raise SbomScannerError("Scanner timeout and output limit must be positive.")
    if checkpoint:
        checkpoint()
    chunks: queue.Queue[tuple[int, bytes | None]] = queue.Queue(maxsize=8)
    stopped = threading.Event()

    def read_stream(index: int, stream: BinaryIO) -> None:
        try:
            while not stopped.is_set():
                chunk = stream.read(65536)
                while not stopped.is_set():
                    try:
                        chunks.put((index, chunk or None), timeout=0.1)
                        break
                    except queue.Full:
                        continue
                if not chunk:
                    break
        finally:
            stream.close()

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name == "posix",
        )
    except OSError as exc:
        raise SbomScannerError("The configured Grype executable could not be started.") from exc
    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=read_stream, args=(index, stream), daemon=True)
        for index, stream in enumerate((process.stdout, process.stderr))
    ]
    for reader in readers:
        reader.start()
    outputs = [bytearray(), bytearray()]
    started = time.monotonic()
    last_checkpoint = started
    ended = 0
    try:
        while ended < 2 or process.poll() is None:
            now = time.monotonic()
            if now - started >= timeout_seconds:
                raise SbomScannerError("The SBOM scanner exceeded its time limit.")
            if checkpoint and now - last_checkpoint >= 0.2:
                checkpoint()
                last_checkpoint = now
            try:
                index, chunk = chunks.get(timeout=0.05)
            except queue.Empty:
                continue
            if chunk is None:
                ended += 1
            else:
                if sum(map(len, outputs)) + len(chunk) > max_output_bytes:
                    raise SbomScannerError("The SBOM scanner exceeded its output size limit.")
                outputs[index].extend(chunk)
        if checkpoint:
            checkpoint()
        if process.returncode:
            detail = outputs[1][-4000:].decode("utf-8", errors="replace").strip()
            raise SbomScannerError(
                f"Grype failed (exit {process.returncode}). "
                f"Check the configured executable and managed vulnerability database. {detail}"
            )
        return bytes(outputs[0]), bytes(outputs[1])
    finally:
        stopped.set()
        _stop_process(process)
        for reader in readers:
            reader.join(timeout=1)


def _database_evidence(
    descriptor: dict[str, Any],
    cache_dir: Path,
) -> tuple[dict[str, str | int | bool], str | None, str | None]:
    db = descriptor.get("db", {})
    if not isinstance(db, dict):
        return {}, None, None
    # Grype versions use either the status itself or a wrapper containing status.
    nested = db.get("status")
    status = nested if isinstance(nested, dict) else db
    if status.get("valid") is False:
        raise SbomScannerError("Grype reported an invalid vulnerability database.")
    metadata = {
        key: value
        for key in ("built", "schemaVersion", "valid", "status", "checksum")
        if isinstance((value := status.get(key)), (str, int, bool)) and len(str(value)) <= 512
    }
    built = _text(status.get("built")) or None
    digest = None
    db_path = _text(status.get("path") or db.get("path"))
    if db_path:
        candidate = Path(db_path).resolve()
        if candidate.is_relative_to(cache_dir) and candidate.is_file():
            with candidate.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
    checksum = _text(status.get("checksum"))
    if not digest and re.fullmatch(r"(?:sha256:)?[a-fA-F0-9]{64}", checksum):
        digest = checksum.removeprefix("sha256:").lower()
    return metadata, built, digest


def _scan_sbom_locked(
    path: Path,
    *,
    executable: str | Path,
    cache_dir: Path,
    target_ref: str | None = None,
    timeout_seconds: float = 120,
    max_output_bytes: int = 64 * 1024 * 1024,
    db_auto_update: bool = False,
    checkpoint: Callable[[], None] | None = None,
) -> SbomScannerResult:
    """Scan only an SBOM using controlled local configuration and bounded resources."""
    with path.open("rb") as stream:
        content = stream.read(_MAX_INPUT_BYTES + 1)
    inventory = inspect_sbom(content, target_ref=target_ref)
    configured = str(executable)
    located = shutil.which(configured) if not Path(configured).is_absolute() else configured
    binary = Path(located or configured).expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SbomScannerError("Configure an installed, executable Grype binary before scanning.")
    cache_dir = cache_dir.expanduser().resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vpw-sbom-") as temporary:
        work = Path(temporary)
        input_path = work / "inventory.json"
        input_path.write_bytes(content)
        config_path = work / "grype.yaml"
        config_path.write_text(
            json.dumps(
                {
                    "check-for-app-update": False,
                    "external-sources": {"enable": False},
                    "db": {
                        "cache-dir": str(cache_dir),
                        "auto-update": db_auto_update,
                        "validate-age": True,
                        "validate-by-hash-on-start": True,
                    },
                    "ignore": [],
                    "exclude": [],
                    "vex-documents": [],
                    "only-fixed": False,
                    "only-notfixed": False,
                    "by-cve": False,
                    "fail-on-severity": "",
                }
            ),
            encoding="utf-8",
        )
        env = {key: value for key, value in os.environ.items() if key.upper() in _ENV_ALLOWLIST}
        env.update({"HOME": str(work), "XDG_CONFIG_HOME": str(work / "config")})
        output, stderr = _run_process(
            [str(binary), "--config", str(config_path), "sbom:" + str(input_path), "-o", "json"],
            cwd=work,
            env=env,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            checkpoint=checkpoint,
        )
    report = _json_object(output, "Grype output")
    matches = report.get("matches")
    if not isinstance(matches, list) or any(not isinstance(m, dict) for m in matches):
        raise SbomScannerError("Grype output must contain a matches array (which may be empty).")
    descriptor = report.get("descriptor")
    if not isinstance(descriptor, dict) or not _text(descriptor.get("version")):
        raise SbomScannerError("Grype output is missing the scanner version.")
    if descriptor.get("name") != "grype":
        raise SbomScannerError("The configured executable did not produce a Grype report.")
    assigned = 0
    for match in matches:
        vulnerability = match.get("vulnerability")
        if not isinstance(vulnerability, dict) or not _text(vulnerability.get("id")):
            raise SbomScannerError("Grype returned a malformed vulnerability match.")
        ids = [vulnerability["id"]]
        for container in (match, vulnerability):
            related = container.get("relatedVulnerabilities", [])
            if isinstance(related, list):
                ids.extend(r.get("id") for r in related if isinstance(r, dict))
        assigned += int(any(_CVE.fullmatch(_text(identifier)) for identifier in ids))
    metadata, built, database_sha256 = _database_evidence(descriptor, cache_dir)
    warnings = list(inventory.warnings)
    if assigned < len(matches):
        warnings.append(f"{len(matches) - assigned} scanner matches have no CVE mapping.")
    if stderr.strip():
        warnings.append(
            "Scanner diagnostics were emitted: "
            + stderr[-4000:].decode("utf-8", errors="replace").strip()
        )
    if report.get("ignoredMatches"):
        warnings.append("Grype reported ignored matches; inspect the original report.")
    if report.get("alertsByPackage"):
        warnings.append("Grype reported package coverage alerts; inspect the original report.")
    if not built or not database_sha256:
        warnings.append("Complete database provenance was unavailable in the scanner report.")
    evidence = SbomAssessmentV1(
        scanner_version=descriptor["version"],
        database_built_at=built,
        database_sha256=database_sha256,
        database_metadata=metadata,
        scanned_at=datetime.now(UTC).isoformat(),
        input_sha256=hashlib.sha256(content).hexdigest(),
        output_sha256=hashlib.sha256(output).hexdigest(),
        target_ref=inventory.target_ref,
        input_format=inventory.input_format,
        component_count=inventory.component_count,
        identified_component_count=inventory.identified_component_count,
        version_missing_count=inventory.version_missing_count,
        scanner_match_count=len(matches),
        prioritized_match_count=assigned,
        unassigned_match_count=len(matches) - assigned,
        warnings=warnings,
        status="partial" if warnings else "complete",
    )
    return SbomScannerResult(report=report, report_bytes=output, evidence=evidence)


def scan_sbom(
    path: Path,
    *,
    executable: str | Path,
    cache_dir: Path,
    target_ref: str | None = None,
    timeout_seconds: float = 120,
    max_output_bytes: int = 64 * 1024 * 1024,
    db_auto_update: bool = False,
    checkpoint: Callable[[], None] | None = None,
) -> SbomScannerResult:
    """Serialize managed DB access and run a bounded, cancellable local assessment."""
    if timeout_seconds <= 0 or max_output_bytes <= 0:
        raise SbomScannerError("Scanner timeout and output limit must be positive.")
    cache_dir = cache_dir.expanduser().resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    lock = FileLock(cache_dir / ".assessment.lock")
    deadline = time.monotonic() + timeout_seconds
    while True:
        if checkpoint:
            checkpoint()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SbomScannerError(
                "The SBOM scanner exceeded its time limit waiting for the cache."
            )
        try:
            lock.acquire(timeout=min(0.1, remaining))
            break
        except Timeout:
            continue
    try:
        return _scan_sbom_locked(
            path,
            executable=executable,
            cache_dir=cache_dir,
            target_ref=target_ref,
            timeout_seconds=max(0.001, deadline - time.monotonic()),
            max_output_bytes=max_output_bytes,
            db_auto_update=db_auto_update,
            checkpoint=checkpoint,
        )
    finally:
        lock.release()
