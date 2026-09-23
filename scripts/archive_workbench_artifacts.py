"""Append one managed artifact root to a portable, symlink-free tar archive."""

from __future__ import annotations

import argparse
import os
import sys
import tarfile
from pathlib import Path

CACHE_ROOTS = {"provider-cache", "provider-snapshots", "workbench-provider-cache"}


def main() -> int:
    """Add regular files and directories, skipping only reconstructible cache links."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.expanduser()
    if root.is_symlink() and root.name in CACHE_ROOTS:
        print("Skipped 1 reconstructible cache symlink.", file=sys.stderr)
        return 0
    if root.is_symlink() or not root.is_dir():
        parser.error("Artifact root must be a regular directory.")
    skipped = 0
    with tarfile.open(args.archive, "a" if args.archive.exists() else "w") as archive:
        for path in (root, *sorted(root.rglob("*"))):
            if path.is_symlink():
                if root.name not in CACHE_ROOTS:
                    parser.error("Managed upload or report tree contains a symlink.")
                skipped += 1
                continue
            if not path.is_file() and not path.is_dir():
                parser.error("Artifact tree contains a non-regular filesystem entry.")
            name = str(Path(root.name) / path.relative_to(root))
            archive.add(path, arcname=name, recursive=False)
    if os.name != "nt":
        args.archive.chmod(0o600)
    if skipped:
        print(f"Skipped {skipped} reconstructible cache symlink(s).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
