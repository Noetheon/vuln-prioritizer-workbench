from __future__ import annotations

from pathlib import Path

import pytest
from scripts import check_release_evidence_hygiene as hygiene
from scripts.check_release_evidence_hygiene import _requirement_key, _uv_requirement_key


def test_uv_metadata_preserves_platform_marker_without_dev_group_selector() -> None:
    requirement = (
        "cryptography>=50.0,<51.0; platform_machine != 'ppc64le' "
        "and platform_machine != 's390x' and sys_platform == 'linux'"
    )
    locked = {
        "name": "cryptography",
        "specifier": ">=50.0,<51.0",
        "marker": (
            "platform_machine != 'ppc64le' and platform_machine != 's390x' "
            "and sys_platform == 'linux' and extra == 'dev'"
        ),
    }

    assert _uv_requirement_key(locked) == _requirement_key(requirement)
    assert _uv_requirement_key({**locked, "marker": "extra == 'dev'"}) != _requirement_key(
        requirement
    )


def test_uv_metadata_dev_selector_does_not_change_unmarked_requirement() -> None:
    assert _uv_requirement_key(
        {"name": "pip", "specifier": ">=26.2,<27.0", "marker": "extra == 'dev'"}
    ) == _requirement_key("pip>=26.2,<27.0")


def test_only_ci_audit_export_setup_may_use_python_311(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hygiene, "ROOT", tmp_path)
    monkeypatch.setattr(hygiene, "WORKFLOW_DIR", tmp_path)
    workflow = tmp_path / "ci.yml"

    def write_workflow(job: str, name: str) -> None:
        workflow.write_text(
            f"jobs:\n  {job}:\n    steps:\n"
            f"      - name: {name}\n"
            "        uses: actions/setup-python@pinned\n"
            "        with:\n          python-version: '3.11'\n",
            encoding="utf-8",
        )

    expected_name = "Set up Python 3.11 for the offline audit-lock export"
    write_workflow("dependency-audit", expected_name)
    assert hygiene._check_workflow_python_versions() == []

    write_workflow("check", expected_name)
    assert "must use Python '3.14'" in hygiene._check_workflow_python_versions()[0]

    write_workflow("dependency-audit", "Set up Python for regular audit")
    assert "must use Python '3.14'" in hygiene._check_workflow_python_versions()[0]
