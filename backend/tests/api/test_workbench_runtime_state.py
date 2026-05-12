from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine

from app.api.deps import get_db
from app.core.app_state import (
    configure_workbench_state,
    fallback_workbench_engine,
    workbench_engine,
    workbench_settings,
)
from app.core.config import Settings, settings
from app.core.db import engine as global_engine


def _request_with_state(**state_values: object) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(**state_values)))


def test_configure_workbench_state_stores_active_state_only() -> None:
    active_settings = Settings(PROJECT_NAME="Runtime State Test")
    active_engine = create_engine("sqlite://")
    app = SimpleNamespace(state=SimpleNamespace())
    try:
        configure_workbench_state(
            app,
            active_settings=active_settings,
            active_engine=active_engine,
        )

        assert app.state.workbench_settings is active_settings
        assert app.state.workbench_engine is active_engine
        assert not hasattr(app.state, "template_settings")
        assert not hasattr(app.state, "template_engine")
    finally:
        active_engine.dispose()


def test_workbench_settings_uses_active_state() -> None:
    active_settings = Settings(PROJECT_NAME="Active Runtime Settings")
    request = _request_with_state(workbench_settings=active_settings)

    assert workbench_settings(request) is active_settings


def test_workbench_settings_returns_global_when_optional_state_is_missing() -> None:
    assert workbench_settings(_request_with_state(), required=False) is settings


def test_workbench_settings_raises_when_required_runtime_state_is_missing() -> None:
    with pytest.raises(HTTPException) as exc_info:
        workbench_settings(_request_with_state())

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Workbench settings are not configured."


def test_workbench_engine_requires_active_state() -> None:
    active_engine = create_engine("sqlite://")
    try:
        assert (
            workbench_engine(_request_with_state(workbench_engine=active_engine)) is active_engine
        )

        with pytest.raises(HTTPException) as missing_exc_info:
            workbench_engine(_request_with_state())
        assert missing_exc_info.value.status_code == 500
        assert missing_exc_info.value.detail == "Workbench database engine is not configured."
    finally:
        active_engine.dispose()


def test_fallback_workbench_engine_uses_active_or_global_engine() -> None:
    active_engine = create_engine("sqlite://")
    try:
        assert fallback_workbench_engine(_request_with_state(workbench_engine=active_engine)) is (
            active_engine
        )
        assert fallback_workbench_engine(_request_with_state()) is global_engine
    finally:
        active_engine.dispose()


def test_get_db_fails_closed_without_active_engine_state() -> None:
    db_dependency = get_db(_request_with_state())

    with pytest.raises(HTTPException) as exc_info:
        next(db_dependency)

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Workbench database engine is not configured."
