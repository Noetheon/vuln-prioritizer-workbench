"""Shared Pydantic model base classes."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base model with frozen instances and forbidden extra fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)
