"""Run quality contracts and require fresh, complete evidence for the current run."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from scripts.select_quality_gates import GATES

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "vpw.quality-receipt.v1"


def write_json(path: Path, payload: dict) -> None:
    """Replace one small evidence document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def read_json(path: Path) -> dict:
    """Reject oversized or non-object evidence rather than silently ignoring it."""
    if path.stat().st_size > 5_000_000:
        raise ValueError(f"Oversized quality evidence: {path.name}")
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"Expected an evidence object: {path.name}")
    return data


def selection(text: str) -> dict[str, bool]:
    """Accept only the complete, explicitly boolean gate selection."""
    data = json.loads(text)
    if not isinstance(data, dict) or set(data) != set(GATES):
        raise ValueError("Missing or unknown quality gate selection")
    if any(type(value) is not bool for value in data.values()):
        raise ValueError("Quality selections must be booleans")
    return data


def context() -> dict[str, str]:
    """Bind every receipt to the repository, exact commit and execution attempt."""
    return {
        "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
        "sha": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
    }


def junit(path: Path) -> dict:
    """Require real, successful cases; an empty or skipped suite is not evidence."""
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    if not cases or any(
        case.find(tag) is not None for case in cases for tag in ("skipped", "failure", "error")
    ):
        raise ValueError(f"Empty, failed or skipped contract: {path.name}")
    return {"tests": len(cases)}


def metrics(root: Path, gate: str, profile: str) -> dict:
    """Extract only compact measurements from the owning check's fresh output."""
    build = root / "build"
    if gate in {"core", "evidence"}:
        result = read_json(build / "mutation" / gate / "results.json")
        campaign = read_json(build / "mutation" / gate / "campaign.json")
        counts = result["counts"]
        total = result["selected_count"]
        if (
            type(total) is not int
            or total <= 0
            or set(counts) - {"killed", "equivalent (reviewed)"}
            or any(type(value) is not int or value < 0 for value in counts.values())
            or sum(counts.values()) != total
            or campaign.get("runner_exit_code") != 0
            or campaign.get("runner_error")
        ):
            raise ValueError("Mutation campaign did not produce successful checked mutations")
        return {
            "mutants": total,
            "killed": counts.get("killed", 0),
            "equivalents": counts.get("equivalent (reviewed)", 0),
            "functions": len(result["patterns"]),
            "mutmut": campaign["mutmut"],
        }
    if gate in {"properties", "recovery", "grype"}:
        path = (
            build / f"property-{profile}.xml"
            if gate == "properties"
            else build / "recovery.xml"
            if gate == "recovery"
            else build / "grype-integration/junit.xml"
        )
        result = junit(path)
        if gate == "grype":
            provenance = read_json(build / "grype-integration/provenance.json")
            if provenance.get("status") != "passed" or result["tests"] != 3:
                raise ValueError("All three real scanner contracts must pass")
            result["scanner_version"] = provenance["scanner"]["version"]
        return result
    history = read_json(build / f"history-performance-{profile}.json")
    smoke = read_json(build / "vpw-072-performance-smoke.json")
    if history.get("status") != "passed" or not history.get("stages"):
        raise ValueError("No successful history workload")
    stages = history["stages"]
    result = {
        "rows": history["rows"],
        "cycles": history["cycles"],
        "revisions": stages[-1]["revision_count"],
        "budgets": history["budgets"],
        "smoke": smoke["measurements"],
        "smoke_budgets": smoke["thresholds"],
    }
    for key in (
        "page_seconds",
        "page_bytes",
        "report_seconds",
        "peak_rss_mib",
        "database_bytes_per_revision",
    ):
        result[key] = max(stage[key] for stage in stages)
    if any(
        type(result[key]) not in (int, float) or not math.isfinite(result[key])
        for key in ("page_seconds", "report_seconds", "peak_rss_mib")
    ):
        raise ValueError("Invalid performance measurements")
    return result


def commands(gate: str, profile: str) -> list[list[str]]:
    """Use the existing Make targets as the single execution boundary."""
    targets = {
        "core": ["mutation-core-check"],
        "evidence": ["mutation-evidence-check"],
        "properties": ["property-extended-check" if profile == "extended" else "property-check"],
        "history": [
            "performance-smoke",
            "history-performance-extended-check"
            if profile == "extended"
            else "history-performance-check",
        ],
        "recovery": ["recovery-check"],
        "grype": ["grype-integration-check"],
    }
    return [["make", target] for target in targets[gate]]


def execute(command: list[str], *, cwd: Path, env: dict) -> None:
    """Bound Make and its subprocess tree, including cleanup after a timeout."""
    process = subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True)
    try:
        code = process.wait(timeout=1500)
        if code:
            raise subprocess.CalledProcessError(code, command)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run_gate(root: Path, gate: str, selected: dict[str, bool], event: str) -> int:
    """Publish a receipt only after checking the real command and its evidence."""
    binding = context()
    profile = "extended" if gate in {"properties", "history"} and event != "pull_request" else "ci"
    receipt = {
        "schema": SCHEMA,
        "context": binding,
        "gate": gate,
        "profile": profile,
        "selected": selected[gate],
        "status": "failed",
        "metrics": {},
        "started_at": datetime.now(UTC).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
            "runner_image": os.environ.get("ImageOS", "local"),
            "runner_version": os.environ.get("ImageVersion", "local"),
        },
    }
    started = time.monotonic()
    try:
        if not selected[gate]:
            receipt["status"] = "not_required"
            return 0
        env = dict(os.environ)
        # Scheduled exploration changes its seed; recording it preserves replay.
        if gate == "properties" and event in {"schedule", "workflow_dispatch"}:
            seed = str(
                int(
                    hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()[:12],
                    16,
                )
            )
            receipt["seed"] = seed
            receipt["hypothesis"] = importlib.metadata.version("hypothesis")
            env["PYTEST_ADDOPTS"] = env.get("PYTEST_ADDOPTS", "") + f" --hypothesis-seed={seed}"
        # Prevent a successful no-op command from consuming a previous run's data.
        stale = {
            "core": ["mutation/core/results.json", "mutation/core/campaign.json"],
            "evidence": ["mutation/evidence/results.json", "mutation/evidence/campaign.json"],
            "properties": [f"property-{profile}.xml"],
            "history": [f"history-performance-{profile}.json", "vpw-072-performance-smoke.json"],
            "recovery": ["recovery.xml"],
            "grype": ["grype-integration/junit.xml", "grype-integration/provenance.json"],
        }
        for name in stale[gate]:
            (root / "build" / name).unlink(missing_ok=True)
        receipt["commands"] = commands(gate, profile)
        for command in receipt["commands"]:
            execute(command, cwd=root, env=env)
        receipt["metrics"] = metrics(root, gate, profile)
        receipt["status"] = "passed"
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        ET.ParseError,
        subprocess.SubprocessError,
    ) as error:
        receipt["error"] = str(error)
        print(f"Quality contract failed: {error}", file=sys.stderr)
        return 1
    finally:
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        receipt["completed_at"] = datetime.now(UTC).isoformat()
        write_json(root / "build/quality-receipts" / f"{gate}.json", receipt)


def verify(receipts: list[dict], selected: dict[str, bool], needs: dict, binding: dict) -> dict:
    """Reject missing, duplicate, stale, skipped and failed required evidence."""
    if set(needs) != {"selection", "policy", "contracts"} or any(
        item.get("result") != "success" for item in needs.values()
    ):
        raise ValueError("Selection, policy and contract jobs must all succeed")
    by_gate = {}
    for receipt in receipts:
        gate = receipt.get("gate")
        if gate not in GATES or gate in by_gate:
            raise ValueError("Unknown or duplicate quality receipt")
        if receipt.get("schema") != SCHEMA or receipt.get("context") != binding:
            raise ValueError("Receipt belongs to another commit, run or attempt")
        if receipt.get("selected") is not selected[gate]:
            raise ValueError("Receipt disagrees with reviewed gate selection")
        expected = "passed" if selected[gate] else "not_required"
        if receipt.get("status") != expected or (selected[gate] and not receipt.get("metrics")):
            raise ValueError(f"Missing successful contract evidence: {gate}")
        by_gate[gate] = receipt
    if set(by_gate) != set(GATES):
        raise ValueError("Missing quality receipts")
    return {
        "schema": "vpw.quality-metrics.v1",
        "context": binding,
        "completed_at": datetime.now(UTC).isoformat(),
        "contracts": by_gate,
    }


def main() -> int:
    """Run a matrix contract or its unconditional final admission check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "verify"))
    parser.add_argument("--gate", choices=GATES)
    parser.add_argument("--receipts", type=Path, default=Path("build/quality-receipts"))
    args = parser.parse_args()
    try:
        selected = selection(os.environ.get("QUALITY_SELECTION", ""))
        if args.mode == "run":
            if args.gate is None:
                parser.error("--gate is required for run")
            return run_gate(ROOT, args.gate, selected, os.environ.get("GITHUB_EVENT_NAME", "local"))
        report = verify(
            [read_json(path) for path in args.receipts.glob("*.json")],
            selected,
            json.loads(os.environ.get("QUALITY_NEEDS", "{}")),
            context(),
        )
        write_json(Path("build/quality-metrics.json"), report)
        print("All selected quality contracts passed for this exact execution.")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Quality admission failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
