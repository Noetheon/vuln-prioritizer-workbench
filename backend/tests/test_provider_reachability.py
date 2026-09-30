from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
import requests

from app.services.provider_reachability import (
    CACHE_SECONDS,
    KEV_MIRROR_DETAIL,
    ProviderReachabilityProbe,
    app_reachability_probe,
)


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _Session:
    """Answers each feed by a keyword in its URL, and records the calls."""

    def __init__(self, answers: dict[str, Any], calls: list[str]) -> None:
        self._answers = answers
        self._calls = calls

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, url: str, **kwargs: Any) -> _Response:
        assert kwargs["stream"] is True
        assert kwargs["timeout"] > 0
        self._calls.append(url)
        for keyword, answer in self._answers.items():
            if keyword in url:
                if isinstance(answer, Exception):
                    raise answer
                return _Response(answer)
        raise AssertionError(url)


def _probe(answers: dict[str, Any], calls: list[str], clock: list[float]):
    return ProviderReachabilityProbe(
        session_factory=lambda: _Session(answers, calls),  # type: ignore[arg-type,return-value]
        clock=lambda: clock[0],
    )


def test_each_feed_reports_whether_it_answered() -> None:
    calls: list[str] = []
    probe = _probe(
        {
            "nvd.nist.gov": 200,
            "first.org": requests.exceptions.ProxyError("tunnel refused"),
            "cisa.gov": requests.Timeout("slow"),
            "githubusercontent.com": requests.ConnectionError("reset"),
        },
        calls,
        [0.0],
    )

    result = probe.check()

    # KEV reports the failure of its primary feed after the mirror failed too.
    assert [(item.source, item.reachable, item.detail) for item in result.sources] == [
        ("nvd", True, None),
        ("epss", False, "Proxy error"),
        ("kev", False, "Timed out"),
    ]
    assert [item.label for item in result.sources] == ["NVD", "EPSS", "KEV"]
    assert len(calls) == 4


def test_kev_answers_through_its_mirror_like_the_provider() -> None:
    calls: list[str] = []
    probe = _probe(
        {
            "nvd.nist.gov": 200,
            "first.org": 200,
            "cisa.gov": requests.ConnectionError("blocked"),
            "githubusercontent.com": 200,
        },
        calls,
        [0.0],
    )

    kev = probe.check().sources[2]

    assert (kev.reachable, kev.detail) == (True, KEV_MIRROR_DETAIL)
    assert len(calls) == 4


def test_http_errors_count_as_unreachable_and_answers_are_cached() -> None:
    calls: list[str] = []
    clock = [100.0]
    probe = _probe({"nvd.nist.gov": 403, "first.org": 200, "cisa.gov": 200}, calls, clock)

    first = probe.check()
    assert [(item.reachable, item.detail) for item in first.sources] == [
        (False, "HTTP 403"),
        (True, None),
        (True, None),
    ]
    # The mirror is only asked when the KEV feed does not answer.
    assert not any("githubusercontent.com" in url for url in calls)
    clock[0] += CACHE_SECONDS - 1
    assert probe.check() is first
    assert len(calls) == 3

    clock[0] += 2
    assert probe.check() is not first
    assert len(calls) == 6


def test_the_app_keeps_one_probe() -> None:
    state = SimpleNamespace()
    probe = app_reachability_probe(state)
    assert app_reachability_probe(state) is probe


@pytest.mark.usefixtures("workbench_api_env")
def test_reachability_route_returns_the_probe_answer(workbench_api_env, monkeypatch) -> None:
    from utils.workbench_env import local_api_headers

    calls: list[str] = []
    probe = _probe({"nvd.nist.gov": 200, "first.org": 200, "cisa.gov": 200}, calls, [0.0])
    monkeypatch.setattr(
        workbench_api_env.client.app.state, "provider_reachability_probe", probe, raising=False
    )

    response = workbench_api_env.client.get(
        "/api/v1/providers/reachability",
        headers=local_api_headers(workbench_api_env.client),
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert [source["reachable"] for source in payload["sources"]] == [True, True, True]
    assert payload["checked_at"]
