"""Check release-evidence docs, audit inputs, and stale wording guardrails."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "backend" / "pyproject.toml"
PYTHON_AUDIT_INPUT = ROOT / "backend" / "requirements.txt"
LEDGER = ROOT / "docs" / "public-production-release-evidence-ledger.md"

STALE_WORDING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "unqualified public-production readiness claim",
        re.compile(
            r"\b(public-production ready|production ready|production-ready|"
            r"ready for public production)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CLI-only product/package claim",
        re.compile(
            r"\b(CLI-only (tool|project|package|application)|"
            r"(is|as|remains) (a )?CLI-only)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "historical template evidence used as closure proof",
        re.compile(
            r"\b(template-era|historical template)[^.:\n]*"
            r"(closes|closure proof|verified-shipped)\b",
            re.IGNORECASE,
        ),
    ),
)

STALE_WORDING_ALLOWLIST: dict[str, tuple[re.Pattern[str], ...]] = {
    "docs/dependency-and-package-policy.md": (re.compile(r"\bnot\s+CLI-only\b", re.IGNORECASE),),
    ".github/pull_request_template.md": (re.compile(r"\bnot claimed\b", re.IGNORECASE),),
}

ACTIVE_DOC_PATHS = (
    ROOT / ".github" / "pull_request_template.md",
    ROOT / "docs" / "release_operations.md",
    ROOT / "docs" / "public-production-release-evidence-ledger.md",
    ROOT / "docs" / "dependency-and-package-policy.md",
)


def main() -> int:
    failures: list[str] = []
    failures.extend(_check_python_audit_input())
    failures.extend(_check_stale_wording())
    failures.extend(_check_ledger())

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print("release evidence hygiene: OK")
    return 0


def _check_python_audit_input() -> list[str]:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    expected_specs = {
        _normalize_requirement(requirement)
        for requirement in project["project"]["dependencies"]
        + project["project"]["optional-dependencies"]["dev"]
    }
    actual_specs = {
        _normalize_requirement(line)
        for line in PYTHON_AUDIT_INPUT.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    expected = {_package_name(requirement) for requirement in expected_specs}
    actual = {_package_name(requirement) for requirement in actual_specs}

    failures: list[str] = []
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        failures.append(
            "backend/requirements.txt is missing pyproject audit dependencies: "
            + ", ".join(missing)
        )
    if extra:
        failures.append(
            "backend/requirements.txt contains dependencies not declared in pyproject: "
            + ", ".join(extra)
        )
    spec_drift = sorted(expected_specs ^ actual_specs)
    if not missing and not extra and spec_drift:
        failures.append(
            "backend/requirements.txt requirement bounds drifted from backend/pyproject.toml: "
            + ", ".join(spec_drift)
        )
    return failures


def _normalize_requirement(requirement: str) -> str:
    return re.sub(r"\s+", "", requirement.strip())


def _package_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
    if not match:
        raise ValueError(f"Could not parse requirement name from {requirement!r}")
    return match.group(1).replace("_", "-").replace(".", "-").lower()


def _check_stale_wording() -> list[str]:
    failures: list[str] = []
    matches = 0
    for path in ACTIVE_DOC_PATHS:
        rel_path = path.relative_to(ROOT).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines, start=1):
            for label, pattern in STALE_WORDING_PATTERNS:
                if not pattern.search(line):
                    continue
                if _is_stale_wording_allowed(rel_path, line):
                    continue
                matches += 1
                failures.append(
                    f"{rel_path}:{line_number}: stale wording audit failed "
                    f"({label}): {line.strip()}"
                )
    if not failures:
        print(f"stale wording audit: OK ({matches} unallowlisted matches)")
    return failures


def _is_stale_wording_allowed(rel_path: str, line: str) -> bool:
    return any(pattern.search(line) for pattern in STALE_WORDING_ALLOWLIST.get(rel_path, ()))


def _check_ledger() -> list[str]:
    text = LEDGER.read_text(encoding="utf-8")
    failures: list[str] = []
    required_columns = (
        "Commit/Tag",
        "Command",
        "Result",
        "Artifact or CI URL",
        "Residual risk",
        "Owner",
        "Follow-up",
    )
    for column in required_columns:
        if column not in text:
            failures.append(f"{LEDGER.relative_to(ROOT)} is missing ledger column: {column}")

    for rel_link in sorted(set(re.findall(r"`((?:docs|build)/[^`]+)`", text))):
        if rel_link.startswith("build/"):
            continue
        if not (ROOT / rel_link).exists():
            failures.append(
                f"{LEDGER.relative_to(ROOT)} links missing local evidence artifact: {rel_link}"
            )

    if not failures:
        print("release ledger structure: OK")
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
