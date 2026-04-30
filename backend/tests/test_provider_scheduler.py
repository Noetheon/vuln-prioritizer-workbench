from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest
from fastapi import HTTPException

from vuln_prioritizer.api.workbench_providers import (
    PROVIDER_UPDATE_LOCK_FILE,
    _provider_update_lock,
)
from vuln_prioritizer.provider_scheduler import (
    ProviderSchedulerConfig,
    build_provider_update_request,
    load_scheduler_config,
    trigger_provider_update,
)
from vuln_prioritizer.workbench_config import WorkbenchSettings


def test_provider_update_lock_rejects_concurrent_refresh(tmp_path) -> None:
    settings = WorkbenchSettings(
        provider_snapshot_dir=tmp_path / "snapshots",
        provider_cache_dir=tmp_path / "cache",
    )

    with _provider_update_lock(settings):
        assert (settings.provider_snapshot_dir / PROVIDER_UPDATE_LOCK_FILE).is_file()
        nested_lock = _provider_update_lock(settings)
        with pytest.raises(HTTPException) as exc_info:
            nested_lock.__enter__()

    assert exc_info.value.status_code == 409
    assert "already running" in str(exc_info.value.detail)
    assert not (settings.provider_snapshot_dir / PROVIDER_UPDATE_LOCK_FILE).exists()


def test_provider_scheduler_env_config_and_request_contract() -> None:
    config = load_scheduler_config(
        {
            "VULN_PRIORITIZER_PROVIDER_UPDATE_BASE_URL": "http://workbench.internal/",
            "VULN_PRIORITIZER_PROVIDER_UPDATE_INTERVAL_SECONDS": "3600",
            "VULN_PRIORITIZER_PROVIDER_UPDATE_SOURCES": "nvd,kev",
            "VULN_PRIORITIZER_PROVIDER_UPDATE_CACHE_ONLY": "false",
            "VULN_PRIORITIZER_PROVIDER_UPDATE_MAX_CVES": "25",
            "VULN_PRIORITIZER_PROVIDER_UPDATE_API_TOKEN": "vpw_token",
            "VULN_PRIORITIZER_PROVIDER_UPDATE_ONCE": "true",
        }
    )
    request = build_provider_update_request(config)

    assert config.interval_seconds == 3600
    assert config.sources == ("nvd", "kev")
    assert config.cache_only is False
    assert config.max_cves == 25
    assert config.once is True
    assert request.full_url == "http://workbench.internal/api/providers/update-jobs"
    assert request.get_method() == "POST"
    assert request.get_header("X-api-token") == "vpw_token"
    assert json.loads(request.data.decode("utf-8")) == {
        "cache_only": False,
        "max_cves": 25,
        "sources": ["nvd", "kev"],
    }


def test_provider_scheduler_defaults_are_cache_only_and_secretless() -> None:
    config = ProviderSchedulerConfig()
    request = build_provider_update_request(config)

    assert config.cache_only is True
    assert config.sources == ("nvd", "epss", "kev")
    assert request.get_header("X-api-token") is None
    assert json.loads(request.data.decode("utf-8")) == {
        "cache_only": True,
        "sources": ["nvd", "epss", "kev"],
    }


def test_provider_scheduler_rejects_unknown_sources() -> None:
    with pytest.raises(ValueError, match="Unsupported provider source"):
        load_scheduler_config({"VULN_PRIORITIZER_PROVIDER_UPDATE_SOURCES": "nvd,unknown"})


def test_provider_scheduler_treats_overlap_conflict_as_blocked(monkeypatch) -> None:
    def raise_conflict(*args, **kwargs):  # noqa: ANN002, ANN003
        raise urllib.error.HTTPError(
            "http://workbench.internal/api/providers/update-jobs",
            409,
            "Conflict",
            hdrs={},
            fp=None,
        )

    monkeypatch.setattr(urllib.request, "urlopen", raise_conflict)

    response = trigger_provider_update(
        ProviderSchedulerConfig(base_url="http://workbench.internal", once=True)
    )

    assert response["status"] == "blocked"
    assert response["metadata"]["http_status"] == 409
