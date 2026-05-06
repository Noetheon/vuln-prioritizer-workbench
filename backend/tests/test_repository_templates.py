from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ISSUE_TEMPLATE_DIR = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"
DEPENDABOT_FILE = REPO_ROOT / ".github" / "dependabot.yml"

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
    "status:needs-docs",
    "status:needs-revalidation",
    "status:needs-review",
    "status:needs-tests",
    "status:strict-dod",
    "status:template-gap",
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


def test_dependabot_labels_exist_and_use_current_frontend_taxonomy() -> None:
    payload = yaml.safe_load(DEPENDABOT_FILE.read_text(encoding="utf-8"))
    labels_by_ecosystem = {
        update["package-ecosystem"]: set(update.get("labels", [])) for update in payload["updates"]
    }
    all_labels = set().union(*labels_by_ecosystem.values())

    assert all_labels - CURRENT_TRACKER_LABELS == set()
    assert "frontend" not in all_labels
    assert labels_by_ecosystem["npm"] >= {"maintenance", "dependencies", "type:frontend", "area:ui"}
