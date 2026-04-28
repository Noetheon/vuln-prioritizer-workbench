"""Test configuration."""

from __future__ import annotations

import sys

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
