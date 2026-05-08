from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine

from app.core.app_state import (
    configure_workbench_state,
    workbench_engine,
    workbench_settings,
)
from app.core.config import Settings, settings
from app.core.db import engine as global_engine


def _request_with_state(**state_values: object) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(**state_values)))


def test_configure_workbench_state_stores_active_and_legacy_aliases() -> None:
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
        assert app.state.template_settings is active_settings
        assert app.state.workbench_engine is active_engine
        assert app.state.template_engine is active_engine
    finally:
        active_engine.dispose()


def test_workbench_settings_prefers_active_state_over_legacy_alias() -> None:
    active_settings = Settings(PROJECT_NAME="Active Runtime Settings")
    legacy_settings = Settings(PROJECT_NAME="Legacy Runtime Settings")
    request = _request_with_state(
        template_settings=legacy_settings,
        workbench_settings=active_settings,
    )

    assert workbench_settings(request) is active_settings


def test_workbench_settings_falls_back_to_legacy_alias_and_global_optional() -> None:
    legacy_settings = Settings(PROJECT_NAME="Legacy Runtime Settings")

    assert (
        workbench_settings(_request_with_state(template_settings=legacy_settings))
        is legacy_settings
    )
    assert workbench_settings(_request_with_state(), required=False) is settings


def test_workbench_settings_raises_when_required_runtime_state_is_missing() -> None:
    with pytest.raises(HTTPException) as exc_info:
        workbench_settings(_request_with_state())

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Workbench settings are not configured."


def test_workbench_engine_prefers_active_state_then_legacy_alias_then_global() -> None:
    active_engine = create_engine("sqlite://")
    legacy_engine = create_engine("sqlite://")
    try:
        assert (
            workbench_engine(
                _request_with_state(
                    template_engine=legacy_engine,
                    workbench_engine=active_engine,
                )
            )
            is active_engine
        )
        assert workbench_engine(_request_with_state(template_engine=legacy_engine)) is legacy_engine
        assert workbench_engine(_request_with_state()) is global_engine
    finally:
        active_engine.dispose()
        legacy_engine.dispose()
