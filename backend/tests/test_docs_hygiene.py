from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml
from paths import REPO_ROOT

MKDOCS_FILE = REPO_ROOT / "mkdocs.yml"
ARCHIVE_ROOT = REPO_ROOT / "archive"
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
# backend report tests. Public and historical evidence belongs in
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
    assert "`build/`" in archive_readme
    assert "`docs/evidence/`" in archive_readme
    assert "`archive/vpw-evidence/`" in archive_readme
    assert "`make clean-local`" in archive_readme
