"""Check pre-commit hooks for immutable remote revisions."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PRE_COMMIT_CONFIG = ROOT / ".pre-commit-config.yaml"
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def main() -> int:
    """Return non-zero when remote pre-commit hooks are not commit-pinned."""
    document = yaml.safe_load(PRE_COMMIT_CONFIG.read_text(encoding="utf-8")) or {}
    repos = document.get("repos")
    if not isinstance(repos, list):
        print(".pre-commit-config.yaml must contain a repos list.", file=sys.stderr)
        return 1

    failures: list[str] = []
    for index, repo_config in enumerate(repos, start=1):
        if not isinstance(repo_config, dict):
            failures.append(f"repos[{index}] is not an object")
            continue
        repo = repo_config.get("repo")
        if repo == "local":
            continue
        rev = repo_config.get("rev")
        if not isinstance(rev, str) or not COMMIT_SHA_RE.fullmatch(rev):
            failures.append(f"repos[{index}] {repo!r} must use a 40-character commit SHA rev")

    if failures:
        print("Remote pre-commit hooks must be pinned by immutable commit SHA:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
