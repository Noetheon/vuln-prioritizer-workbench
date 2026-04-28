from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path


def main() -> int:
    dist_dir = Path("dist")
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if not wheels or not sdists:
        print("Expected wheel and sdist in dist/.", file=sys.stderr)
        return 1
    for path in [*wheels, *sdists]:
        names = _archive_names(path)
        index_names = [
            name for name in names if name.endswith("vuln_prioritizer/web/static/app/index.html")
        ]
        js_names = [name for name in names if _is_static_asset(name, ".js")]
        css_names = [name for name in names if _is_static_asset(name, ".css")]
        if not index_names or not js_names or not css_names:
            print(f"{path} is missing React Workbench static assets.", file=sys.stderr)
            return 1
    print("React Workbench static assets are present in wheel and sdist.")
    return 0


def _archive_names(path: Path) -> set[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return set(archive.namelist())
    with tarfile.open(path) as archive:
        return set(archive.getnames())


def _is_static_asset(name: str, suffix: str) -> bool:
    return "vuln_prioritizer/web/static/app/assets/" in name and name.endswith(suffix)


if __name__ == "__main__":
    raise SystemExit(main())
