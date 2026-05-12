"""Alembic helpers for the local Workbench schema."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
ALEMBIC_HEAD = ""


def _alembic_config(config_path: Path | None = None) -> Config:
    active_config_path = config_path or ALEMBIC_INI
    config = Config(str(active_config_path)) if active_config_path.exists() else Config()
    if not config.get_main_option("script_location"):
        config.set_main_option("script_location", str(resources.files("app.alembic")))
    return config


def current_alembic_head(config_path: Path | None = None) -> str:
    """Return the current Alembic script head from the configured migration path."""
    config = _alembic_config(config_path)
    head = ScriptDirectory.from_config(config).get_current_head()
    if not head:
        raise RuntimeError("Alembic migration head could not be resolved.")
    return head


ALEMBIC_HEAD = current_alembic_head()


def main() -> None:
    """Validate that the packaged Workbench migration head can be resolved."""
    current_alembic_head()


if __name__ == "__main__":
    main()
