"""Test configuration."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
TESTS_PATH = PROJECT_ROOT / "tests"

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
