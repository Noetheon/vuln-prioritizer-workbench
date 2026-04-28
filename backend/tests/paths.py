from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "backend"
SRC_ROOT = BACKEND_ROOT / "src"
TESTS_ROOT = BACKEND_ROOT / "tests"
DATA_ROOT = REPO_ROOT / "data"
DOCS_ROOT = REPO_ROOT / "docs"
