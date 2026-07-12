"""Test configuration."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest
import requests
from paths import REPO_ROOT, SRC_ROOT, TESTS_ROOT

PROJECT_ROOT = REPO_ROOT
SRC_PATH = SRC_ROOT
TESTS_PATH = TESTS_ROOT

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))
if str(TESTS_PATH) not in sys.path:
    sys.path.insert(0, str(TESTS_PATH))

_GLOBAL_RUNTIME_ROOT = Path(tempfile.mkdtemp(prefix="vpw-pytest-runtime-"))
_GLOBAL_RUNTIME_ENV = {
    "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(_GLOBAL_RUNTIME_ROOT / 'workbench.db').as_posix()}",
    "IMPORT_UPLOAD_DIR": str(_GLOBAL_RUNTIME_ROOT / "imports"),
    "REPORT_DIR": str(_GLOBAL_RUNTIME_ROOT / "reports"),
    "PROVIDER_CACHE_DIR": str(_GLOBAL_RUNTIME_ROOT / "provider-cache"),
    "PROVIDER_SNAPSHOT_DIR": str(_GLOBAL_RUNTIME_ROOT / "provider-snapshots"),
}
_INTRODUCED_RUNTIME_ENV = frozenset(name for name in _GLOBAL_RUNTIME_ENV if name not in os.environ)
for _name, _value in _GLOBAL_RUNTIME_ENV.items():
    os.environ.setdefault(_name, _value)

pytest_plugins = ("utils.workbench_env",)


@pytest.fixture(autouse=True)
def _hide_global_runtime_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _INTRODUCED_RUNTIME_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _block_live_network(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if request.node.get_closest_marker("live_network"):
        return

    def blocked_request(self, method, url, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise RuntimeError(
            "Live network access is disabled for tests. "
            "Use @pytest.mark.live_network when a test intentionally reaches the network."
        )

    monkeypatch.setattr(requests.sessions.Session, "request", blocked_request)
