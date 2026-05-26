"""Check GitHub workflows for pinned remote actions and safe checkout settings."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
USES_RE = re.compile(r"^\s*uses:\s*(?P<value>[^#\n]+)")
REMOTE_ACTION_SHA_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)


def main() -> int:
    """Return non-zero when workflow actions or checkout settings are unsafe."""
    pin_failures: list[str] = []
    checkout_failures: list[str] = []
    for workflow in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_RE.match(line)
            if match is None:
                continue
            value = _unquote(match.group("value").strip())
            if _is_local_action(value):
                continue
            if value.startswith("docker://"):
                if "@sha256:" not in value:
                    pin_failures.append(f"{workflow.relative_to(ROOT)}:{line_number}: {value}")
                continue
            if not REMOTE_ACTION_SHA_RE.fullmatch(value):
                pin_failures.append(f"{workflow.relative_to(ROOT)}:{line_number}: {value}")

        checkout_failures.extend(_checkout_credential_failures(workflow))

    if pin_failures:
        print("GitHub workflow remote actions must be pinned by commit SHA:", file=sys.stderr)
        for failure in pin_failures:
            print(f"- {failure}", file=sys.stderr)
    if checkout_failures:
        print("GitHub checkout steps must disable persisted credentials:", file=sys.stderr)
        for failure in checkout_failures:
            print(f"- {failure}", file=sys.stderr)

    if pin_failures or checkout_failures:
        return 1
    return 0


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _is_local_action(value: str) -> bool:
    return value.startswith(("./", "../"))


def _checkout_credential_failures(workflow: Path) -> list[str]:
    document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
    jobs = document.get("jobs", {})
    if not isinstance(jobs, dict):
        return []

    failures: list[str] = []
    for job_name, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if not isinstance(uses, str) or not uses.startswith("actions/checkout@"):
                continue
            with_config = step.get("with")
            if (
                not isinstance(with_config, dict)
                or with_config.get("persist-credentials") is not False
            ):
                failures.append(f"{workflow.relative_to(ROOT)}:jobs.{job_name}.steps[{index}]")
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
