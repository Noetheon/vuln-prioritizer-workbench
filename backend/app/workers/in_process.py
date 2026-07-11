"""Supervised in-process runtime for the durable workflow worker."""

from __future__ import annotations

import logging
import os
import threading
import uuid
from collections.abc import Callable

from sqlalchemy.engine import Engine

from app.core.config import Settings
from app.workers.workflow_worker import run_worker_loop

logger = logging.getLogger(__name__)


class InProcessWorkflowWorker:
    """Run and restart the durable DB worker inside the local API process."""

    def __init__(
        self,
        *,
        engine: Engine,
        settings: Settings,
        poll_interval_seconds: float = 2.0,
        restart_delay_seconds: float = 0.25,
        runner: Callable[..., None] = run_worker_loop,
    ) -> None:
        self.engine = engine
        self.settings = settings
        self.poll_interval_seconds = max(0.1, poll_interval_seconds)
        self.restart_delay_seconds = max(0.05, restart_delay_seconds)
        self.runner = runner
        self.worker_id = f"in-process-{os.getpid()}-{uuid.uuid4()}"
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.restart_count = 0
        self.last_error: str | None = None

    @property
    def is_alive(self) -> bool:
        """Return whether the supervised worker thread is currently alive."""
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the worker once; repeated startup calls are harmless."""
        with self._lock:
            if self.is_alive:
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._supervise,
                name="vpw-workflow-worker",
                daemon=True,
            )
            self._thread.start()

    def stop(self, *, timeout_seconds: float = 10.0) -> None:
        """Request a graceful stop and wait for the active worker tick."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.1, timeout_seconds))
            if thread.is_alive():
                logger.warning("In-process workflow worker did not stop before timeout.")

    def _supervise(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.runner(
                    engine=self.engine,
                    settings=self.settings,
                    worker_id=self.worker_id,
                    poll_interval_seconds=self.poll_interval_seconds,
                    stop_event=self._stop_event,
                )
            except Exception as exc:  # pragma: no cover - exact failures are runner-specific
                self.restart_count += 1
                self.last_error = f"{type(exc).__name__}: {exc}"
                logger.exception("In-process workflow worker crashed; restarting.")
                if self._stop_event.wait(self.restart_delay_seconds):
                    return
