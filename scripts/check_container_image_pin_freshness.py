"""
Compare pinned OCI image digests with their current registry tags.

This is a scheduled review aid for same-tag image rebuilds. Dependabot handles
new versions, but a registry can republish a stable tag with OS fixes without
changing its version number.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE_FILES = (
    ROOT / "backend" / "Dockerfile",
    ROOT / "frontend" / "Dockerfile",
    ROOT / "frontend" / "Dockerfile.playwright",
    ROOT / "docker" / "security-tools" / "Dockerfile",
    ROOT / "compose.yml",
    ROOT / "compose.traefik.yml",
    ROOT / "Makefile",
)
IMAGE_LINE = re.compile(
    r"^\s*(?:FROM\s+|image:\s*|[A-Z0-9_]*IMAGE\s*(?:\?=|:=|=)\s*)(?P<image>\S+)",
    re.IGNORECASE,
)
PIN = re.compile(r"^(?P<tag>[^@\s]+)@sha256:(?P<digest>[0-9a-f]{64})$")


def pinned_images(path: Path) -> list[tuple[int, str]]:
    """Return static image references in a Dockerfile, Compose file or Makefile."""
    result: list[tuple[int, str]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = IMAGE_LINE.match(line)
        if match is None:
            continue
        image = match.group("image")
        if "$" not in image:
            result.append((line_number, image))
    return result


def current_digest(tag: str) -> str:
    """Hash the raw registry manifest, preserving a multi-platform index."""
    manifest = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", "--raw", tag],
        check=True,
        capture_output=True,
    ).stdout
    return hashlib.sha256(manifest).hexdigest()


def main() -> int:
    """Return nonzero for stale pins or registry lookup errors."""
    failures: list[str] = []
    resolved: dict[str, str] = {}
    checked = 0
    for path in IMAGE_FILES:
        for line_number, image in pinned_images(path):
            location = f"{path.relative_to(ROOT)}:{line_number}"
            pin = PIN.fullmatch(image)
            if pin is None:
                failures.append(f"{location}: static image reference is not digest-pinned: {image}")
                continue
            tag, expected = pin.group("tag", "digest")
            try:
                if tag not in resolved:
                    resolved[tag] = current_digest(tag)
                actual = resolved[tag]
            except subprocess.CalledProcessError as exc:
                reason = exc.stderr.decode(errors="replace").strip() or str(exc)
                failures.append(f"{location}: could not inspect {tag}: {reason}")
                continue
            checked += 1
            if actual != expected:
                failures.append(
                    f"{location}: {tag} now resolves to sha256:{actual}; pinned sha256:{expected}"
                )

    if failures:
        print("Container image pin review needs attention:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Container image pin review: {checked} references match their current tags.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
