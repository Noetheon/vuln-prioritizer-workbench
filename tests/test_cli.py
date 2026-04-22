from __future__ import annotations

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _cli_helpers import install_fake_providers as _shared_install_fake_providers  # noqa: E402
from _cli_helpers import runner as _shared_runner  # noqa: E402
from _cli_helpers import write_input_file as _shared_write_input_file  # noqa: E402

_install_fake_providers = _shared_install_fake_providers
runner = _shared_runner
_write_input_file = _shared_write_input_file
