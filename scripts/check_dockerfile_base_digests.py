"""Check Docker and Compose image references for digest pins."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

FROM_RE = re.compile(r"^\s*FROM\s+(?P<image>\S+)", re.IGNORECASE)
MAKE_IMAGE_RE = re.compile(r"^\s*(?P<name>[A-Z0-9_]*IMAGE)\s*(?:\?=|:=|=)\s*(?P<image>\S+)")
ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = (
    ROOT / "backend" / "Dockerfile",
    ROOT / "frontend" / "Dockerfile",
    ROOT / "frontend" / "Dockerfile.playwright",
)
COMPOSE_FILES = (
    ROOT / "compose.yml",
    ROOT / "compose.traefik.yml",
)
MAKEFILES = (ROOT / "Makefile",)


def _requires_digest(image: str) -> bool:
    return bool(image.strip()) and "$" not in image


def main() -> int:
    """Return non-zero when a required image reference is not digest-pinned."""
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

    for makefile in MAKEFILES:
        for line_number, line in enumerate(makefile.read_text(encoding="utf-8").splitlines(), 1):
            match = MAKE_IMAGE_RE.match(line)
            if match is None:
                continue
            image = match.group("image")
            if not _requires_digest(image):
                continue
            if "@sha256:" not in image:
                failures.append(
                    f"{makefile.relative_to(ROOT)}:{line_number}:{match.group('name')}: {image}"
                )

    if failures:
        print("Container base and static service images must be pinned by digest:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
