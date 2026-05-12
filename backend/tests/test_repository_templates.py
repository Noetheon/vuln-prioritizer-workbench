from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ISSUE_TEMPLATE_DIR = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"
DEPENDABOT_FILE = REPO_ROOT / ".github" / "dependabot.yml"
PULL_REQUEST_TEMPLATE = REPO_ROOT / ".github" / "pull_request_template.md"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPO_ROOT / "Makefile"

CURRENT_TRACKER_LABELS = {
    "area:api",
    "area:attack",
    "area:ci",
    "area:core",
    "area:docs",
    "area:governance",
    "area:parser",
    "area:provider",
    "area:report",
    "area:security",
    "area:ui",
    "bug",
    "dependencies",
    "documentation",
    "duplicate",
    "enhancement",
    "github-actions",
    "good first issue",
    "help wanted",
    "invalid",
    "maintenance",
    "priority:critical",
    "priority:high",
    "priority:low",
    "priority:medium",
    "priority:p0",
    "priority:p1",
    "priority:p2",
    "python",
    "question",
    "risk:data-quality",
    "risk:demo",
    "risk:provider-api",
    "risk:scope",
    "risk:security",
    "status:blocked",
    "status:architecture-decision",
    "status:needs-docs",
    "status:needs-revalidation",
    "status:needs-review",
    "status:needs-tests",
    "status:strict-dod",
    "type:api",
    "type:attack",
    "type:backend",
    "type:db",
    "type:docs",
    "type:epic",
    "type:feature",
    "type:frontend",
    "type:governance",
    "type:parser",
    "type:provider",
    "type:refactor",
    "type:release",
    "type:report",
    "type:security",
    "type:task",
    "type:test",
    "wontfix",
}


def _front_matter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), path
    _, payload, _ = text.split("---", 2)
    return yaml.safe_load(payload)


def _labels(value: str | None) -> set[str]:
    if not value:
        return set()
    return {label.strip() for label in value.split(",") if label.strip()}


def test_issue_template_default_labels_exist_in_current_taxonomy() -> None:
    missing: dict[str, set[str]] = {}

    for path in sorted(ISSUE_TEMPLATE_DIR.glob("*.md")):
        labels = _labels(_front_matter(path).get("labels"))
        unknown = labels - CURRENT_TRACKER_LABELS
        if unknown:
            missing[path.name] = unknown

    assert missing == {}


def test_issue_templates_keep_strict_evidence_sections() -> None:
    missing: list[str] = []

    for path in sorted(ISSUE_TEMPLATE_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        if "## Definition Of Done" not in text or "## Evidence" not in text:
            missing.append(path.name)

    assert missing == []


def test_general_templates_do_not_make_release_hardening_the_default() -> None:
    generic_templates = [
        ISSUE_TEMPLATE_DIR / "bug_report.md",
        ISSUE_TEMPLATE_DIR / "feature_request.md",
        PULL_REQUEST_TEMPLATE,
    ]
    forbidden_phrases = [
        "public deployment certification",
        "Public deployment certification",
        "final scorecard",
        "mandatory release-readiness",
    ]

    offenders: dict[str, list[str]] = {}
    for path in generic_templates:
        text = path.read_text(encoding="utf-8")
        matched = [phrase for phrase in forbidden_phrases if phrase in text]
        if matched:
            offenders[path.name] = matched

    assert offenders == {}


def test_default_ci_uses_local_workbench_gate_not_release_or_package_gate() -> None:
    ci_workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    local_gate = makefile.split("\nperformance-smoke:", maxsplit=1)[0]

    assert "run: make local-workbench-check" in ci_workflow
    assert "run: make workflow-check" not in ci_workflow
    assert "local-workbench-check:" in makefile
    assert "$(MAKE) check" in local_gate
    assert "$(MAKE) docs-check" in local_gate
    assert "$(MAKE) package-check" not in local_gate
    assert "$(MAKE) docker-production-smoke" not in local_gate
    assert "$(MAKE) release-readiness-check" not in local_gate


def test_dependabot_labels_exist_and_use_current_frontend_taxonomy() -> None:
    payload = yaml.safe_load(DEPENDABOT_FILE.read_text(encoding="utf-8"))
    labels_by_ecosystem = {
        update["package-ecosystem"]: set(update.get("labels", [])) for update in payload["updates"]
    }
    all_labels = set().union(*labels_by_ecosystem.values())

    assert all_labels - CURRENT_TRACKER_LABELS == set()
    assert "frontend" not in all_labels
    assert labels_by_ecosystem["npm"] >= {"maintenance", "dependencies", "type:frontend", "area:ui"}
