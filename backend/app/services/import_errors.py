"""Domain errors for Workbench import services."""

from __future__ import annotations

from typing import Any


class ImportServiceError(RuntimeError):
    """Raised by import services when the route layer should return an error."""

    def __init__(self, *, status_code: int, detail: str | dict[str, Any]) -> None:
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail
