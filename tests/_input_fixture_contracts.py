from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_FILE = PROJECT_ROOT / "data" / "input_fixtures" / "normalization_contracts.json"


def load_input_fixture_contracts() -> dict[str, Any]:
    return json.loads(CONTRACTS_FILE.read_text(encoding="utf-8"))
