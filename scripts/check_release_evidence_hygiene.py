"""Check release-evidence docs, audit inputs, and stale wording guardrails."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
MKDOCS_FILE = ROOT / "mkdocs.yml"
PYPROJECT = ROOT / "backend" / "pyproject.toml"
README = ROOT / "README.md"
PYTHON_AUDIT_INPUT = ROOT / "backend" / "requirements.txt"
PYTHON_AUDIT_LOCK = ROOT / "backend" / "requirements.lock.txt"
PYTHON_RUNTIME_LOCK = ROOT / "backend" / "requirements.runtime.lock.txt"
PYTHON_LOCK = ROOT / "uv.lock"
LEDGER = ROOT / "docs" / "public-production-release-evidence-ledger.md"
WORKFLOW_DIR = ROOT / ".github" / "workflows"
RUNTIME_PYTHON_VERSION = "3.13"
SUPPORTED_PYTHON_VERSIONS = ("3.11", "3.12", RUNTIME_PYTHON_VERSION)
SETUP_PYTHON_MATRIX_EXPRESSION = "${{ matrix.python-version }}"
RUNTIME_LOCK_FORBIDDEN_PACKAGES = {
    "build",
    "mkdocs",
    "mypy",
    "pip-audit",
    "pre-commit",
    "pytest",
    "pytest-cov",
    "ruff",
    "twine",
}

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
            r"default secrets|defaults|backend))\b",
            re.IGNORECASE,
        ),
    ),
)

STALE_WORDING_ALLOWLIST: dict[str, tuple[re.Pattern[str], ...]] = {
    "docs/dependency-and-package-policy.md": (re.compile(r"\bnot\s+CLI-only\b", re.IGNORECASE),),
    ".github/pull_request_template.md": (re.compile(r"\bnot claimed\b", re.IGNORECASE),),
    "docs/current-product-state.md": (re.compile(r"\bnot\s+a\s+CLI-only\b", re.IGNORECASE),),
    "docs/documentation-map.md": (
        re.compile(r"\bCLI-only product claims\b", re.IGNORECASE),
        re.compile(r"\bunqualified public-production readiness claims\b", re.IGNORECASE),
        re.compile(r"\btemplate-era evidence as closure proof\b", re.IGNORECASE),
    ),
    "docs/workbench-public-deployment.md": (
        re.compile(r"\btemplate\.db\b", re.IGNORECASE),
        re.compile(r"\btemplate-[a-z0-9-]+\b", re.IGNORECASE),
        re.compile(r"\bcompatibility names\b", re.IGNORECASE),
    ),
}

# These pages are intentionally historical or compatibility inventory. They stay
# in public navigation, but stale wording inside them is not a current product
# claim when the page status is explicit.
STALE_WORDING_HISTORICAL_DOC_PATHS = {
    Path("docs/full_stack_fastapi_template_migration.md"),
    Path("docs/vpw_template_execution_sequence.md"),
    Path("docs/architecture/template-replacement.md"),
    Path("docs/architecture/template-service-layer.md"),
    Path("docs/architecture/vpw-013-importer-contract.md"),
}

NON_NAV_STALE_WORDING_PATHS = (ROOT / ".github" / "pull_request_template.md",)


def main() -> int:
    """Run release-evidence hygiene checks and print a compact status line."""
    failures: list[str] = []
    failures.extend(_check_python_audit_input())
    failures.extend(_check_workflow_python_versions())
    failures.extend(_check_package_metadata_maturity())
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
    runtime_requirements = project["project"]["dependencies"]
    dev_requirements = project["project"]["optional-dependencies"]["dev"]
    audit_requirements = runtime_requirements + dev_requirements
    expected_specs = {_normalize_requirement(requirement) for requirement in audit_requirements}
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
    failures.extend(_check_python_audit_lock(audit_requirements))
    failures.extend(_check_python_runtime_lock(runtime_requirements, dev_requirements))
    return failures


def _check_workflow_python_versions() -> list[str]:
    failures: list[str] = []
    for workflow in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        jobs = document.get("jobs", {})
        if not isinstance(jobs, dict):
            continue
        for job_name, job in sorted(jobs.items()):
            if not isinstance(job, dict):
                continue
            matrix_versions = _workflow_python_matrix_versions(job)
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for index, step in enumerate(steps, 1):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if not isinstance(uses, str) or not uses.startswith("actions/setup-python@"):
                    continue
                with_config = step.get("with")
                python_version = (
                    with_config.get("python-version") if isinstance(with_config, dict) else None
                )
                location = f"{workflow.relative_to(ROOT)}:jobs.{job_name}.steps[{index}]"
                if python_version == SETUP_PYTHON_MATRIX_EXPRESSION:
                    if matrix_versions != SUPPORTED_PYTHON_VERSIONS:
                        failures.append(
                            f"{location} must use the supported Python matrix "
                            f"{list(SUPPORTED_PYTHON_VERSIONS)!r}."
                        )
                    continue
                if python_version != RUNTIME_PYTHON_VERSION:
                    failures.append(
                        f"{location} must use Python {RUNTIME_PYTHON_VERSION!r} or "
                        f"{SETUP_PYTHON_MATRIX_EXPRESSION!r} for the supported-version matrix."
                    )

    if not failures:
        print("workflow Python version policy: OK")
    return failures


def _workflow_python_matrix_versions(job: dict[str, object]) -> tuple[str, ...]:
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        return ()
    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict):
        return ()
    versions = matrix.get("python-version")
    if not isinstance(versions, list) or not all(isinstance(version, str) for version in versions):
        return ()
    return tuple(versions)


def _check_package_metadata_maturity() -> list[str]:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    classifiers = set(project.get("classifiers", []))
    failures: list[str] = []
    beta_classifier = "Development Status :: 4 - Beta"
    stable_classifier = "Development Status :: 5 - Production/Stable"
    if beta_classifier not in classifiers:
        failures.append(f"backend/pyproject.toml is missing {beta_classifier!r}.")
    if stable_classifier in classifiers:
        failures.append(
            "backend/pyproject.toml must not claim Production/Stable until "
            "public-production evidence is certified."
        )

    readme = README.read_text(encoding="utf-8")
    ledger = LEDGER.read_text(encoding="utf-8")
    for path, text in ((README, readme), (LEDGER, ledger)):
        if beta_classifier not in text:
            failures.append(
                f"{path.relative_to(ROOT)} must explain the current package maturity "
                f"classifier {beta_classifier!r}."
            )

    if not failures:
        print("package metadata maturity: OK")
    return failures


def _check_python_audit_lock(expected_requirements: list[str]) -> list[str]:
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

    audit_lock_packages = _pinned_lock_package_names(
        audit_lock_text,
        "backend/requirements.lock.txt",
    )
    missing_audit_lock_packages = sorted(expected_names - audit_lock_packages)
    if missing_audit_lock_packages:
        failures.append(
            "backend/requirements.lock.txt is missing direct pyproject dependencies: "
            + ", ".join(missing_audit_lock_packages)
        )

    return failures


def _check_python_runtime_lock(
    runtime_requirements: list[str],
    dev_requirements: list[str],
) -> list[str]:
    if not PYTHON_RUNTIME_LOCK.exists():
        return [
            "backend/requirements.runtime.lock.txt is missing; export it from uv.lock "
            "before building the backend Docker image."
        ]

    runtime_lock_text = PYTHON_RUNTIME_LOCK.read_text(encoding="utf-8")
    failures: list[str] = []
    if "autogenerated by uv" not in runtime_lock_text or "--locked" not in runtime_lock_text:
        failures.append(
            "backend/requirements.runtime.lock.txt must be exported from uv.lock with uv export."
        )
    for expected_fragment in (
        "--package vuln-prioritizer",
        "--no-dev",
        "--python 3.13",
        "backend/requirements.runtime.lock.txt",
    ):
        if expected_fragment not in runtime_lock_text:
            failures.append(
                "backend/requirements.runtime.lock.txt export command is missing "
                f"{expected_fragment}."
            )
    if "--all-extras" in runtime_lock_text:
        failures.append(
            "backend/requirements.runtime.lock.txt must not be exported with --all-extras."
        )
    if "--hash=sha256:" not in runtime_lock_text:
        failures.append("backend/requirements.runtime.lock.txt must include package hashes.")

    runtime_lock_packages = _pinned_lock_package_names(
        runtime_lock_text,
        "backend/requirements.runtime.lock.txt",
    )
    runtime_names = {_package_name(requirement) for requirement in runtime_requirements}
    missing_runtime_packages = sorted(runtime_names - runtime_lock_packages)
    if missing_runtime_packages:
        failures.append(
            "backend/requirements.runtime.lock.txt is missing direct runtime dependencies: "
            + ", ".join(missing_runtime_packages)
        )

    dev_names = {_package_name(requirement) for requirement in dev_requirements}
    forbidden_runtime_packages = sorted(
        runtime_lock_packages & (dev_names | RUNTIME_LOCK_FORBIDDEN_PACKAGES)
    )
    if forbidden_runtime_packages:
        failures.append(
            "backend/requirements.runtime.lock.txt contains dev/audit-only packages: "
            + ", ".join(forbidden_runtime_packages)
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


def _pinned_lock_package_names(lock_text: str, lock_label: str) -> set[str]:
    packages: set[str] = set()
    for line in lock_text.splitlines():
        if not line or line.startswith((" ", "#")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==[^\\\s;]+(?:\s*;.*)?(?:\s*\\)?$", line)
        if not match:
            raise ValueError(f"Unexpected unlocked requirement in {lock_label}: {line}")
        packages.add(_package_name(match.group(1)))
    return packages


def _check_stale_wording() -> list[str]:
    failures: list[str] = []
    matches = 0
    for path in _stale_wording_scan_paths():
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


def _stale_wording_scan_paths() -> list[Path]:
    mkdocs_config = yaml.safe_load(MKDOCS_FILE.read_text(encoding="utf-8"))
    nav_pages = _nav_markdown_pages(mkdocs_config["nav"])
    current_pages = [
        ROOT / page for page in nav_pages if page not in STALE_WORDING_HISTORICAL_DOC_PATHS
    ]
    all_pages = [*current_pages, *NON_NAV_STALE_WORDING_PATHS]
    return sorted({path for path in all_pages if path.exists()})


def _nav_markdown_pages(node: Any) -> set[Path]:
    pages: set[Path] = set()
    if isinstance(node, str):
        if node.endswith(".md"):
            pages.add(Path("docs") / node)
        return pages
    if isinstance(node, list):
        for item in node:
            pages.update(_nav_markdown_pages(item))
        return pages
    if isinstance(node, dict):
        for value in node.values():
            pages.update(_nav_markdown_pages(value))
    return pages


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
