"""Run a bounded fresh mutation campaign and retain reviewable evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path

from check_mutmut_results import main as check_results
from filelock import FileLock, Timeout

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    """Run the selected policy with the current configured Python environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("core", "evidence", "all"), default="all")
    parser.add_argument("--max-children", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    if args.max_children < 1 or args.timeout < 1:
        parser.error("child count and timeout must be positive")
    if os.name != "posix":
        parser.error("mutmut requires POSIX process isolation; use Linux, macOS, or WSL")
    try:
        with FileLock(str(ROOT / "backend" / ".mutation-check.lock"), timeout=0):
            return run_campaign(args)
    except Timeout:
        print("Another mutation campaign already owns this checkout.", file=sys.stderr)
        return 1


def run_campaign(args: argparse.Namespace) -> int:
    """Own the generated mutant tree for one bounded campaign."""
    backend = ROOT / "backend"
    policy_path = backend / "mutation-policy.toml"
    policy = tomllib.loads(policy_path.read_text())
    groups = ("core", "evidence") if args.profile == "all" else (args.profile,)
    patterns = [pattern for group in groups for pattern in policy[group]["patterns"]]
    output = ROOT / "build" / "mutation" / args.profile
    output.mkdir(parents=True, exist_ok=True)
    config = tomllib.loads((backend / "pyproject.toml").read_text())["tool"]["mutmut"]
    sources = {
        name: hashlib.sha256((backend / name).read_bytes()).hexdigest()
        for name in config["source_paths"]
    }
    metadata = {
        "schema": "vpw.mutation-campaign.v1",
        "profile": args.profile,
        "patterns": patterns,
        "source_sha256": sources,
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "equivalents_sha256": hashlib.sha256(
            (backend / "mutation-equivalents.json").read_bytes()
        ).hexdigest(),
        "test_sha256": {
            name: hashlib.sha256((backend / name).read_bytes()).hexdigest()
            for name in config["pytest_add_cli_args_test_selection"]
        },
        "python": sys.version,
        "mutmut": importlib.metadata.version("mutmut"),
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "timeout_seconds": args.timeout,
        "max_children": args.max_children,
    }
    report = output / "results.json"
    report.unlink(missing_ok=True)
    started = time.monotonic()
    command = [
        sys.executable,
        "-m",
        "mutmut",
        "run",
        "--max-children",
        str(args.max_children),
        *patterns,
    ]
    print(f"Mutation profile {args.profile}; log: {output / 'run.log'}", flush=True)
    try:
        # Refuse to reuse a tree that could not be removed. A cached result
        # must never be reported as evidence for the current source hashes.
        if (backend / "mutants").exists():
            shutil.rmtree(backend / "mutants")
        with (output / "run.log").open("w") as log:
            process = subprocess.Popen(
                command,
                cwd=backend,
                stdout=log,
                stderr=subprocess.STDOUT,
                env={**os.environ, "TERM": "dumb", "NO_COLOR": "1", "VPW_PROPERTY_PROFILE": "ci"},
                start_new_session=True,
            )
            try:
                return_code = process.wait(timeout=args.timeout)
            finally:
                # Reap forkserver/workers as well, including after a crashed parent.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        metadata["runner_exit_code"] = return_code
        status = check_results(
            [
                "check_mutmut_results.py",
                str(backend / "mutants"),
                *patterns,
                "--report",
                str(report),
                "--equivalents",
                str(backend / "mutation-equivalents.json"),
            ]
        )
        if return_code:
            status = 1
    except (OSError, subprocess.TimeoutExpired) as error:
        metadata["runner_error"] = str(error)
        print(f"Mutation infrastructure failed: {error}", file=sys.stderr)
        status = 1
    finally:
        metadata["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "campaign.json").write_text(json.dumps(metadata, indent=2) + "\n")
    if status:
        print(f"Mutation gate failed; inspect {output}", file=sys.stderr)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
