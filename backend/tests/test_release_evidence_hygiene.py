from __future__ import annotations

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
