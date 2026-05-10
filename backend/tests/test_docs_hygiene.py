from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml
from paths import REPO_ROOT

MKDOCS_FILE = REPO_ROOT / "mkdocs.yml"
README_FILE = REPO_ROOT / "README.md"
ARCHIVE_ROOT = REPO_ROOT / "archive"
REPORTS_AND_EVIDENCE_FILE = REPO_ROOT / "docs" / "reports-and-evidence.md"
CURRENT_PRODUCT_STATE_FILE = REPO_ROOT / "docs" / "current-product-state.md"
DOCUMENTATION_MAP_FILE = REPO_ROOT / "docs" / "documentation-map.md"
PYPROJECT_FILE = REPO_ROOT / "backend" / "pyproject.toml"
GITHUB_READINESS_FILE = REPO_ROOT / "docs" / "github-open-source-readiness.md"
RELEASE_OPERATIONS_FILE = REPO_ROOT / "docs" / "release_operations.md"
COMMUNITY_SETUP_FILE = REPO_ROOT / "docs" / "community_repository_setup.md"
GITHUB_ISSUE_TEMPLATE_ROOT = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"
MAINTAINERS_FILE = REPO_ROOT / "MAINTAINERS.md"
SUPPORT_FILE = REPO_ROOT / "SUPPORT.md"
TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
MEDIA_SUFFIXES = {".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp"}
CANONICAL_EVIDENCE_CONTRACT_ARTIFACTS = {
    Path("docs/evidence/vpw-050-analysis-result.v1.json"),
    Path("docs/evidence/vpw-050-findings.csv"),
    Path("docs/evidence/vpw-051-analysis.json"),
    Path("docs/evidence/vpw-051-manifest.json"),
    Path("docs/evidence/vpw-052-positive-verification.json"),
    Path("docs/evidence/vpw-052-tampered-verification.json"),
    Path("docs/evidence/vpw-054-report-snapshots.md"),
    Path("docs/evidence/vpw-060-attack-navigator-layer.json"),
}
# docs/evidence is intentionally kept only for contract artifacts validated by
# backend contract tests. Public and historical evidence belongs in
# archive/vpw-evidence so broad evidence sprawl cannot return unnoticed.
NON_PUBLIC_CONTRACT_MARKDOWN = {
    path for path in CANONICAL_EVIDENCE_CONTRACT_ARTIFACTS if path.suffix.lower() == ".md"
}


def _git_ls_files(*patterns: str) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", *patterns],
        check=True,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        text=True,
    )
    paths = [Path(line) for line in result.stdout.splitlines() if line]
    return sorted({path for path in paths if (REPO_ROOT / path).exists()})


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


def _tracked_text_corpus() -> str:
    chunks: list[str] = []
    for path in _git_ls_files():
        if path.parts and path.parts[0] == "archive":
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        chunks.append((REPO_ROOT / path).read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)


def _issue_template_labels() -> set[str]:
    labels: set[str] = set()
    for path in sorted(GITHUB_ISSUE_TEMPLATE_ROOT.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        if not text.startswith("---"):
            continue
        try:
            raw_metadata = text.split("---", 2)[1]
        except IndexError:
            continue
        metadata = yaml.safe_load(raw_metadata) or {}
        raw_labels = metadata.get("labels", "")
        if isinstance(raw_labels, str):
            labels.update(label.strip() for label in raw_labels.split(",") if label.strip())
    return labels


def test_mkdocs_nav_includes_all_public_markdown_pages() -> None:
    mkdocs_config = yaml.safe_load(MKDOCS_FILE.read_text(encoding="utf-8"))
    nav_pages = _nav_markdown_pages(mkdocs_config["nav"])
    docs_pages = {
        path
        for path in _git_ls_files("docs")
        if path.suffix.lower() == ".md" and path not in NON_PUBLIC_CONTRACT_MARKDOWN
    }

    assert docs_pages - nav_pages == set()


def test_public_docs_media_are_referenced() -> None:
    corpus = _tracked_text_corpus()
    unreferenced: list[str] = []

    for path in _git_ls_files("docs"):
        if path.suffix.lower() not in MEDIA_SUFFIXES:
            continue
        docs_relative = path.relative_to("docs").as_posix()
        candidates = {path.as_posix(), docs_relative, path.name}
        if not any(candidate in corpus for candidate in candidates):
            unreferenced.append(path.as_posix())

    assert unreferenced == []


def test_screenshot_tests_do_not_write_directly_to_public_docs() -> None:
    scanned_paths = [
        *sorted((REPO_ROOT / "frontend" / "tests").glob("*.ts")),
        *sorted((REPO_ROOT / "backend" / "tests").rglob("*.py")),
    ]
    scanned_paths = [path for path in scanned_paths if path.name != "test_docs_hygiene.py"]
    forbidden = ("../docs/evidence", "docs/evidence", "docs/ui-productization")
    violations = {
        str(path.relative_to(REPO_ROOT)): token
        for path in scanned_paths
        for token in forbidden
        if token in path.read_text(encoding="utf-8", errors="ignore")
    }

    assert violations == {}


def test_tracked_tree_excludes_local_artifacts() -> None:
    blocked_exact = {
        ".coverage",
        "backend-uvicorn.log",
        "frontend-vite.log",
    }
    blocked_parts = {
        ".cache",
        ".mypy_cache",
        ".playwright-cli",
        ".playwright-mcp",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "node_modules",
        "site",
        "test-results",
    }
    violations = []
    for path in _git_ls_files():
        parts = set(path.parts)
        if path.name == ".DS_Store" or path.as_posix() in blocked_exact:
            violations.append(path.as_posix())
            continue
        if parts & blocked_parts or path.suffix in {".pyc", ".pyo"}:
            violations.append(path.as_posix())

    assert violations == []


def test_gitignore_covers_workbench_runtime_artifacts() -> None:
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    required_runtime_roots = {
        "data/workbench-import-uploads/",
        "data/workbench-reports/",
        "data/workbench-provider-cache/",
        "data/provider-snapshots/",
        "data/template-import-uploads/",
        "data/template-reports/",
        "data/template-provider-cache/",
        "data/template-provider-snapshots/",
    }

    assert {path for path in required_runtime_roots if path not in gitignore} == set()


def test_testpypi_release_docs_do_not_mix_package_indexes() -> None:
    runbook = RELEASE_OPERATIONS_FILE.read_text(encoding="utf-8")
    testpypi_section = runbook.split("## TestPyPI Validation Path", maxsplit=1)[1].split(
        "## CI Cost Policy",
        maxsplit=1,
    )[0]

    assert "--extra-index-url" not in testpypi_section
    assert "--no-deps" in testpypi_section
    assert "--only-binary=:all:" in testpypi_section


def test_issue_template_labels_are_documented() -> None:
    documented_labels = COMMUNITY_SETUP_FILE.read_text(encoding="utf-8")
    undocumented_labels = {
        label for label in _issue_template_labels() if f"`{label}`" not in documented_labels
    }

    assert undocumented_labels == set()


def test_archives_have_entrypoints_and_public_evidence_tree_is_limited() -> None:
    evidence_files = set(_git_ls_files("docs/evidence"))
    nested_evidence_files = {
        path for path in evidence_files if len(path.relative_to(Path("docs/evidence")).parts) > 1
    }
    media_artifacts = {path for path in evidence_files if path.suffix.lower() in MEDIA_SUFFIXES}

    assert evidence_files == CANONICAL_EVIDENCE_CONTRACT_ARTIFACTS
    assert nested_evidence_files == set()
    assert media_artifacts == set()

    assert (ARCHIVE_ROOT / "README.md").is_file()
    assert (ARCHIVE_ROOT / "vpw-evidence" / "README.md").is_file()
    assert (ARCHIVE_ROOT / "vpw-evidence" / "MANIFEST.md").is_file()
    assert (ARCHIVE_ROOT / "historical-planning" / "README.md").is_file()

    archive_readme = (ARCHIVE_ROOT / "README.md").read_text(encoding="utf-8")
    archive_manifest = (ARCHIVE_ROOT / "vpw-evidence" / "MANIFEST.md").read_text(encoding="utf-8")
    reports_and_evidence = REPORTS_AND_EVIDENCE_FILE.read_text(encoding="utf-8")
    assert "`build/`" in archive_readme
    assert "`docs/evidence/`" in archive_readme
    assert "`archive/vpw-evidence/`" in archive_readme
    assert "`git status --short --ignored`" in archive_readme
    assert "`make clean-local`" in archive_readme
    assert "`make clean-deps`" in archive_readme
    assert "not release evidence" in archive_readme
    assert "Do not delete user-local artifacts" in archive_readme

    assert "Evidence Ownership Matrix" in reports_and_evidence
    assert "CI artifacts" in reports_and_evidence
    assert "Historical screenshots" in reports_and_evidence
    assert "do not copy raw artifacts into `docs/evidence/`" in reports_and_evidence

    assert "Ownership Rules" in archive_manifest
    assert "Update this manifest" in archive_manifest
    assert "Do not archive secrets" in archive_manifest


def test_documentation_map_defines_current_and_historical_boundaries() -> None:
    mkdocs = yaml.safe_load(MKDOCS_FILE.read_text(encoding="utf-8"))
    nav_pages = _nav_markdown_pages(mkdocs["nav"])
    current_product_pages = _nav_markdown_pages(
        next(
            item["Current Product State"]
            for item in mkdocs["nav"]
            if "Current Product State" in item
        )
    )
    history_pages = _nav_markdown_pages(
        next(item["Workbench History"] for item in mkdocs["nav"] if "Workbench History" in item)
    )
    current_state = CURRENT_PRODUCT_STATE_FILE.read_text(encoding="utf-8")
    documentation_map = DOCUMENTATION_MAP_FILE.read_text(encoding="utf-8")
    pyproject = PYPROJECT_FILE.read_text(encoding="utf-8")

    assert Path("docs/current-product-state.md") in nav_pages
    assert Path("docs/documentation-map.md") in nav_pages
    assert Path("docs/workbench-threat-model.md") in current_product_pages
    assert Path("docs/workbench-public-deployment.md") in current_product_pages
    assert Path("docs/workbench-threat-model.md") not in history_pages
    assert Path("docs/workbench-public-deployment.md") not in history_pages
    assert "FastAPI" in current_state
    assert "`backend/app`" in current_state
    assert "React, Vite, TypeScript" in current_state
    assert "CLI and domain core" in current_state
    assert "Historical evidence in `archive/**`" in current_state
    assert "Development Status :: 4 - Beta" in current_state
    assert "Development Status :: 4 - Beta" in pyproject
    assert "Development Status :: 5 - Production/Stable" not in pyproject
    assert "Source-Of-Truth Order" in documentation_map
    assert "Historical Reference" in documentation_map
    assert "Must not be used as current completion evidence" in documentation_map
    assert "Package maturity" in documentation_map


def test_github_open_source_entrypoints_are_linked_and_versioned() -> None:
    mkdocs = yaml.safe_load(MKDOCS_FILE.read_text(encoding="utf-8"))
    nav_pages = _nav_markdown_pages(mkdocs["nav"])
    readme = README_FILE.read_text(encoding="utf-8")
    documentation_map = DOCUMENTATION_MAP_FILE.read_text(encoding="utf-8")
    github_readiness = GITHUB_READINESS_FILE.read_text(encoding="utf-8")
    community_setup = COMMUNITY_SETUP_FILE.read_text(encoding="utf-8")
    maintainers = MAINTAINERS_FILE.read_text(encoding="utf-8")
    support = SUPPORT_FILE.read_text(encoding="utf-8")

    assert Path("docs/github-open-source-readiness.md") in nav_pages
    for path in (
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "SUPPORT.md",
        "MAINTAINERS.md",
        "CHANGELOG.md",
        "docs/github-open-source-readiness.md",
    ):
        assert path in readme

    assert "Open-source repository health" in documentation_map
    assert "GitHub-Side Settings Checklist" in github_readiness
    assert "`MAINTAINERS.md`" in github_readiness
    assert "`SECURITY.md`" in github_readiness
    assert "`CONTRIBUTING.md`" in github_readiness
    assert "`SUPPORT.md`" in github_readiness
    assert "`CODE_OF_CONDUCT.md`" in github_readiness
    assert "Release Ownership" in maintainers
    assert "Security issues follow `SECURITY.md`" in maintainers
    assert "github-open-source-readiness.md" in support
    assert "GitHub Open Source Readiness" in community_setup
