"""Bounded, reproducible generated-test budgets shared by local and CI runs."""

from __future__ import annotations

import os

from hypothesis import settings


def property_settings(*, stateful: bool = False) -> settings:
    """Select an explicit budget without changing the properties under test."""
    profile = os.environ.get("VPW_PROPERTY_PROFILE", "ci")
    if profile not in {"ci", "extended"}:
        raise ValueError("VPW_PROPERTY_PROFILE must be ci or extended")
    extended = profile == "extended"
    return settings(
        deadline=None,
        derandomize=True,
        max_examples=(40 if extended else 8) if stateful else (250 if extended else 50),
        stateful_step_count=25 if extended else 8,
        print_blob=True,
    )
