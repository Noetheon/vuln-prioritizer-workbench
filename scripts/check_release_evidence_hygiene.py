"""Check release-evidence docs, audit inputs, and stale wording guardrails."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "backend" / "pyproject.toml"
PYTHON_AUDIT_INPUT = ROOT / "backend" / "requirements.txt"
PYTHON_AUDIT_LOCK = ROOT / "backend" / "requirements.lock.txt"
PYTHON_LOCK = ROOT / "uv.lock"
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
    (
        "active Workbench docs still describe product behavior as template behavior",
        re.compile(
            r"\btemplate(?:[- ](?:scoped|service-token|service tokens|imports?|import|"
            r"Workbench|runs?|finding|findings|API|auth|token routes|"
            r"default secrets|defaults))\b",
            re.IGNORECASE,
        ),
    ),
)

STALE_WORDING_ALLOWLIST: dict[str, tuple[re.Pattern[str], ...]] = {
    "docs/dependency-and-package-policy.md": (re.compile(r"\bnot\s+CLI-only\b", re.IGNORECASE),),
    ".github/pull_request_template.md": (re.compile(r"\bnot claimed\b", re.IGNORECASE),),
    "docs/workbench-public-deployment.md": (
        re.compile(r"\btemplate\.db\b", re.IGNORECASE),
        re.compile(r"\btemplate-[a-z0-9-]+\b", re.IGNORECASE),
        re.compile(r"\bcompatibility names\b", re.IGNORECASE),
    ),
}

ACTIVE_DOC_PATHS = (
    ROOT / ".github" / "pull_request_template.md",
    ROOT / "docs" / "contracts.md",
    ROOT / "docs" / "release_operations.md",
    ROOT / "docs" / "workbench-threat-model.md",
    ROOT / "docs" / "workbench-public-deployment.md",
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
    expected_requirements = (
        project["project"]["dependencies"] + project["project"]["optional-dependencies"]["dev"]
    )
    expected_specs = {_normalize_requirement(requirement) for requirement in expected_requirements}
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
    failures.extend(_check_python_lock(expected_requirements))
    return failures


def _check_python_lock(expected_requirements: list[str]) -> list[str]:
    failures: list[str] = []
    expected_names = {_package_name(requirement) for requirement in expected_requirements}
    expected_keys = {_requirement_key(requirement) for requirement in expected_requirements}

    if not PYTHON_LOCK.exists():
        return ["uv.lock is missing; refresh it with uv lock before release evidence handoff."]
    if not PYTHON_AUDIT_LOCK.exists():
        return [
            "backend/requirements.lock.txt is missing; export it from uv.lock before "
            "running dependency-audit."
        ]

    lock = tomllib.loads(PYTHON_LOCK.read_text(encoding="utf-8"))
    members = set(lock.get("manifest", {}).get("members", []))
    if {"vuln-prioritizer", "vuln-prioritizer-workbench-workspace"} - members:
        failures.append("uv.lock does not describe the backend workspace members.")

    packages = {
        _package_name(str(package["name"])): package
        for package in lock.get("package", [])
        if "name" in package
    }
    missing_locked_packages = sorted(expected_names - packages.keys())
    if missing_locked_packages:
        failures.append(
            "uv.lock is missing direct pyproject dependencies: "
            + ", ".join(missing_locked_packages)
        )

    backend_package = packages.get("vuln-prioritizer")
    if backend_package is None:
        failures.append("uv.lock is missing the editable vuln-prioritizer backend package.")
    else:
        locked_keys = {
            _uv_requirement_key(requirement)
            for requirement in backend_package.get("metadata", {}).get("requires-dist", [])
        }
        missing_locked_specs = sorted(expected_keys - locked_keys)
        if missing_locked_specs:
            failures.append(
                "uv.lock backend metadata drifted from backend/pyproject.toml: "
                + ", ".join(_format_requirement_key(item) for item in missing_locked_specs)
            )

    audit_lock_text = PYTHON_AUDIT_LOCK.read_text(encoding="utf-8")
    if "autogenerated by uv" not in audit_lock_text or "--locked" not in audit_lock_text:
        failures.append(
            "backend/requirements.lock.txt must be exported from uv.lock with uv export."
        )
    if "--hash=sha256:" not in audit_lock_text:
        failures.append("backend/requirements.lock.txt must include package hashes.")

    audit_lock_packages = _pinned_lock_package_names(audit_lock_text)
    missing_audit_lock_packages = sorted(expected_names - audit_lock_packages)
    if missing_audit_lock_packages:
        failures.append(
            "backend/requirements.lock.txt is missing direct pyproject dependencies: "
            + ", ".join(missing_audit_lock_packages)
        )

    return failures


def _normalize_requirement(requirement: str) -> str:
    return re.sub(r"\s+", "", requirement.strip())


RequirementKey = tuple[str, tuple[str, ...], str]


def _requirement_key(requirement: str) -> RequirementKey:
    normalized = _normalize_requirement(requirement)
    match = re.match(
        r"^([A-Za-z0-9_.-]+)"
        r"(?:\[([A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*)\])?(.*)$",
        normalized,
    )
    if not match:
        raise ValueError(f"Could not parse requirement from {requirement!r}")
    extras = tuple(
        sorted(_package_name(extra) for extra in (match.group(2) or "").split(",") if extra)
    )
    return (_package_name(match.group(1)), extras, match.group(3))


def _uv_requirement_key(requirement: dict[str, object]) -> RequirementKey:
    name = str(requirement["name"])
    extras = tuple(sorted(_package_name(str(extra)) for extra in requirement.get("extras", [])))
    return (_package_name(name), extras, str(requirement.get("specifier", "")))


def _format_requirement_key(requirement: RequirementKey) -> str:
    name, extras, specifier = requirement
    extras_label = f"[{','.join(extras)}]" if extras else ""
    return f"{name}{extras_label}{specifier}"


def _package_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
    if not match:
        raise ValueError(f"Could not parse requirement name from {requirement!r}")
    return match.group(1).replace("_", "-").replace(".", "-").lower()


def _pinned_lock_package_names(lock_text: str) -> set[str]:
    packages: set[str] = set()
    for line in lock_text.splitlines():
        if not line or line.startswith((" ", "#")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==[^\\\s;]+(?:\s*;.*)?(?:\s*\\)?$", line)
        if not match:
            raise ValueError(
                f"Unexpected unlocked requirement in backend/requirements.lock.txt: {line}"
            )
        packages.add(_package_name(match.group(1)))
    return packages


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
