from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

FROM_RE = re.compile(r"^\s*FROM\s+(?P<image>\S+)", re.IGNORECASE)
ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = (
    ROOT / "backend" / "Dockerfile",
    ROOT / "frontend" / "Dockerfile",
)
COMPOSE_FILES = (
    ROOT / "compose.yml",
    ROOT / "compose.traefik.yml",
)


def _requires_digest(image: str) -> bool:
    return bool(image.strip()) and "$" not in image


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

    for compose_file in COMPOSE_FILES:
        document = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
        services = document.get("services", {})
        if not isinstance(services, dict):
            continue
        for service_name, service in sorted(services.items()):
            if not isinstance(service, dict):
                continue
            image = service.get("image")
            if not isinstance(image, str) or not _requires_digest(image):
                continue
            if "@sha256:" not in image:
                failures.append(
                    f"{compose_file.relative_to(ROOT)}:services.{service_name}.image: {image}"
                )

    if failures:
        print("Container base and static service images must be pinned by digest:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
