from __future__ import annotations

import re
import sys
from pathlib import Path

FROM_RE = re.compile(r"^\s*FROM\s+(?P<image>\S+)", re.IGNORECASE)
ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = (
    ROOT / "backend" / "Dockerfile",
    ROOT / "frontend" / "Dockerfile",
)


def main() -> int:
    failures: list[str] = []
    for dockerfile in DOCKERFILES:
        for line_number, line in enumerate(dockerfile.read_text(encoding="utf-8").splitlines(), 1):
            match = FROM_RE.match(line)
            if match is None:
                continue
            image = match.group("image")
            if "@sha256:" not in image:
                failures.append(f"{dockerfile.relative_to(ROOT)}:{line_number}: {image}")

    if failures:
        print("Dockerfile base images must be pinned by digest:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
