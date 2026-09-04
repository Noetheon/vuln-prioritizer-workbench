from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from app.core.config import settings
from app.services.project_lifecycle_lock import (
    ProjectLifecycleBusyError,
    lock_project_lifecycle,
)


def test_project_lifecycle_lock_distinguishes_async_tasks_on_one_thread(
    tmp_path: Path,
) -> None:
    """Logical requests must not inherit another task's same-thread ownership."""
    active_settings = replace(settings, REPORT_DIR=str(tmp_path / "reports"))
    project_id = uuid.uuid4()

    async def exercise_contention() -> list[str]:
        first_entered = asyncio.Event()
        release_first = asyncio.Event()
        outcomes: list[str] = []

        async def first_task() -> None:
            with lock_project_lifecycle(active_settings, project_id):
                outcomes.append("first-entered")
                first_entered.set()
                await release_first.wait()

        async def second_task() -> None:
            await first_entered.wait()
            with pytest.raises(ProjectLifecycleBusyError):
                with lock_project_lifecycle(active_settings, project_id):
                    outcomes.append("second-entered")
            outcomes.append("second-busy")
            release_first.set()

        await asyncio.gather(first_task(), second_task())
        return outcomes

    assert asyncio.run(exercise_contention()) == ["first-entered", "second-busy"]


def test_project_lifecycle_lock_releases_for_next_request(tmp_path: Path) -> None:
    active_settings = replace(settings, REPORT_DIR=str(tmp_path / "reports"))
    project_id = uuid.uuid4()

    with lock_project_lifecycle(active_settings, project_id):
        pass
    with lock_project_lifecycle(active_settings, project_id) as lease:
        assert lease.project_id == project_id
