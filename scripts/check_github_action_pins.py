from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
USES_RE = re.compile(r"^\s*uses:\s*(?P<value>[^#\n]+)")
REMOTE_ACTION_SHA_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)


def main() -> int:
    failures: list[str] = []
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
                    failures.append(f"{workflow.relative_to(ROOT)}:{line_number}: {value}")
                continue
            if not REMOTE_ACTION_SHA_RE.fullmatch(value):
                failures.append(f"{workflow.relative_to(ROOT)}:{line_number}: {value}")

    if failures:
        print("GitHub workflow remote actions must be pinned by commit SHA:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _is_local_action(value: str) -> bool:
    return value.startswith(("./", "../"))


if __name__ == "__main__":
    raise SystemExit(main())
