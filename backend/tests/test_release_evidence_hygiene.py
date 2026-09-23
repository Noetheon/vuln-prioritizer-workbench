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


@pytest.mark.parametrize(
    ("filename", "job"),
    [("ci.yml", "dependency-audit"), ("release.yml", "build-and-release")],
)
def test_audit_export_jobs_set_up_python_311_before_runtime(
    filename: str, job: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hygiene, "ROOT", tmp_path)
    monkeypatch.setattr(hygiene, "WORKFLOW_DIR", tmp_path)
    workflow = tmp_path / filename

    def write_workflow(
        versions: tuple[str, ...], name: str = hygiene.AUDIT_EXPORT_SETUP_NAME
    ) -> None:
        steps = "".join(
            f"      - name: {name if version == '3.11' else 'Set up Python'}\n"
            "        uses: actions/setup-python@pinned\n"
            f"        with:\n          python-version: '{version}'\n"
            for version in versions
        )
        workflow.write_text(
            f"jobs:\n  {job}:\n    steps:\n{steps}",
            encoding="utf-8",
        )

    write_workflow(("3.11", "3.14"))
    assert hygiene._check_workflow_python_versions() == []

    write_workflow(("3.14", "3.11"))
    ordering_error = "must set up Python 3.11 before Python 3.14"
    assert ordering_error in hygiene._check_workflow_python_versions()[0]

    write_workflow(("3.14",))
    assert ordering_error in hygiene._check_workflow_python_versions()[0]

    write_workflow(("3.11", "3.14"), "Set up Python for regular audit")
    assert "must use Python '3.14'" in hygiene._check_workflow_python_versions()[0]
