"""
Build and verify SPDX inventories tied to the bytes of each release archive.

The wheel/sdist inventories describe their packaged files and declared
Requires-Dist metadata. The local ZIP inventory additionally describes the
*referenced* uv/npm lock entries; it does not claim that those dependencies are
installed in the source bundle. The accompanying provenance is unsigned,
self-reported CI context, not a SLSA attestation or proof of builder identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tomllib
import zipfile
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import BinaryIO
from urllib.parse import quote

PROJECT = "vuln-prioritizer-workbench"
REPOSITORY = "https://github.com/Noetheon/vuln-prioritizer-workbench"
SCHEMA = "release-artifact-evidence.v1"
REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40,64}")
MAX_LOCK_BYTES = 20 * 1024 * 1024
BUILD_INPUT_PATHS = (
    "uv.lock",
    "backend/requirements.lock.txt",
    "backend/pyproject.toml",
    "frontend/package-lock.json",
)
RELEASE_TOOLS = ("build", "pip", "setuptools", "twine", "wheel")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_path(name: str) -> str:
    if not name or "\\" in name or "\0" in name or name.startswith("/") or ":" in name:
        raise ValueError(f"Unsafe archive path: {name!r}")
    parts = name.rstrip("/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"Unsafe archive path: {name!r}")
    return "/".join(parts)


def _hash_stream(handle: BinaryIO) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()  # SPDX 2.3 package verification-code algorithm.
    size = 0
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        sha256.update(chunk)
        sha1.update(chunk)
        size += len(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), size


def _read_zip(path: Path) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    records: list[dict[str, object]] = []
    selected: dict[str, bytes] = {}
    seen: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = _archive_path(info.filename)
            if name in seen:
                raise ValueError(f"Duplicate archive path: {name}")
            seen.add(name)
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError(f"Non-regular archive entry: {name}")
            if info.is_dir():
                continue
            if kind == stat.S_IFDIR or info.flag_bits & 1:
                raise ValueError(f"Invalid archive file: {name}")
            with archive.open(info) as handle:
                sha256, sha1, size = _hash_stream(handle)
            if size != info.file_size:
                raise ValueError(f"Archive file size mismatch: {name}")
            records.append({"name": name, "size": size, "sha256": sha256, "sha1": sha1})
            if (
                name.endswith(".dist-info/METADATA")
                or name.endswith("/BUNDLE-MANIFEST.json")
                or name.endswith("/uv.lock")
                or name.endswith("/frontend/package-lock.json")
                or name.endswith("/backend/pyproject.toml")
                or name.endswith("/backend/requirements.lock.txt")
            ):
                if size > MAX_LOCK_BYTES:
                    raise ValueError(f"Release metadata is too large: {name}")
                selected[name] = archive.read(info)
    return sorted(records, key=lambda item: str(item["name"])), selected


def _read_sdist(path: Path) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    records: list[dict[str, object]] = []
    selected: dict[str, bytes] = {}
    seen: set[str] = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = _archive_path(member.name)
            if name in seen:
                raise ValueError(f"Duplicate archive path: {name}")
            seen.add(name)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"Non-regular archive entry: {name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError(f"Unreadable archive entry: {name}")
            with handle:
                sha256, sha1, size = _hash_stream(handle)
            if size != member.size:
                raise ValueError(f"Archive file size mismatch: {name}")
            records.append({"name": name, "size": size, "sha256": sha256, "sha1": sha1})
            if name.count("/") == 1 and name.endswith("/PKG-INFO"):
                if size > MAX_LOCK_BYTES:
                    raise ValueError(f"Release metadata is too large: {name}")
                metadata_handle = archive.extractfile(member)
                if metadata_handle is None:
                    raise ValueError(f"Unreadable release metadata: {name}")
                with metadata_handle:
                    selected[name] = metadata_handle.read()
    return sorted(records, key=lambda item: str(item["name"])), selected


def _single_metadata(selected: dict[str, bytes], suffix: str) -> bytes:
    matches = [value for name, value in selected.items() if name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {suffix} in release artifact; found {len(matches)}")
    return matches[0]


def _validate_build_inputs(
    data: bytes, bundle: Path, commit: str, ref: str | None, run_url: str | None
) -> None:
    """Check that reported build inputs agree with the shipped source bundle."""
    payload = json.loads(data)
    if not isinstance(payload, dict) or payload.get("schema_version") != "release-build-inputs.v1":
        raise ValueError("Invalid release build-inputs schema")
    if (
        payload.get("commit") != commit
        or payload.get("ref") != ref
        or payload.get("run_url") != run_url
    ):
        raise ValueError("Build-inputs source or workflow context mismatch")
    if not isinstance(payload.get("python"), str) or not isinstance(payload.get("uv"), str):
        raise ValueError("Invalid release build toolchain record")
    _records, selected = _read_zip(bundle)
    recorded_hashes = payload.get("input_sha256")
    if not isinstance(recorded_hashes, dict) or set(recorded_hashes) != set(BUILD_INPUT_PATHS):
        raise ValueError("Build-inputs lockfile set mismatch")
    for path in BUILD_INPUT_PATHS:
        actual = hashlib.sha256(_single_metadata(selected, f"/{path}")).hexdigest()
        if recorded_hashes[path] != actual:
            raise ValueError(f"Build-inputs checksum differs from source bundle: {path}")
    lock = tomllib.loads(_single_metadata(selected, "/uv.lock").decode("utf-8"))
    locked = {
        item["name"]: item["version"] for item in lock["package"] if item["name"] in RELEASE_TOOLS
    }
    reported = payload.get("locked_and_installed_tools")
    if not isinstance(reported, dict) or set(reported) != set(RELEASE_TOOLS) or reported != locked:
        raise ValueError("Build-inputs release tools differ from bundled uv.lock")


def _metadata_dependencies(data: bytes, version: str) -> list[dict[str, str]]:
    metadata = BytesParser(policy=policy.default).parsebytes(data)
    name = str(metadata.get("Name", ""))
    if re.sub(r"[-_.]+", "-", name).lower() != PROJECT or metadata.get("Version") != version:
        raise ValueError(
            f"Distribution metadata name/version mismatch: {name} {metadata.get('Version')}"
        )
    dependencies = []
    for raw in metadata.get_all("Requires-Dist", []):
        requirement = str(raw)
        match = REQUIREMENT_NAME.match(requirement)
        if match is None:
            raise ValueError(f"Invalid Requires-Dist metadata: {requirement!r}")
        dependencies.append(
            {"ecosystem": "pypi", "name": match.group(), "requirement": requirement}
        )
    return sorted(dependencies, key=lambda item: item["requirement"])


def _bundle_dependencies(
    selected: dict[str, bytes], version: str
) -> tuple[list[dict[str, str]], str]:
    manifest = json.loads(_single_metadata(selected, "/BUNDLE-MANIFEST.json"))
    if (
        manifest.get("schema_version") != "release-bundle-manifest.v1"
        or manifest.get("version") != version
    ):
        raise ValueError("Bundle manifest schema/version mismatch")
    pyproject = tomllib.loads(_single_metadata(selected, "/backend/pyproject.toml").decode())
    if pyproject["project"]["name"] != PROJECT or pyproject["project"]["version"] != version:
        raise ValueError("Bundle backend project metadata mismatch")
    uv_lock = tomllib.loads(_single_metadata(selected, "/uv.lock").decode())
    npm_lock = json.loads(_single_metadata(selected, "/frontend/package-lock.json"))
    dependencies: list[dict[str, str]] = []
    for item in uv_lock.get("package", []):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("version"), str)
        ):
            raise ValueError("Invalid uv.lock package entry")
        source = item.get("source")
        registry_url = source.get("registry") if isinstance(source, dict) else None
        if isinstance(registry_url, str):
            source_type = (
                "pypi registry"
                if registry_url.rstrip("/")
                in {"https://pypi.org/simple", "https://pypi.python.org/simple"}
                else "other registry"
            )
        else:
            source_type = "local or non-registry"
        dependencies.append(
            {
                "ecosystem": "pypi",
                "name": item["name"],
                "version": item["version"],
                "lock_path": "uv.lock",
                "scope": "locked reference; environment/extra markers may apply",
                "source": source_type,
            }
        )
    packages = npm_lock.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("frontend/package-lock.json has no packages map")
    for path, item in packages.items():
        if path == "":
            continue
        if (
            not isinstance(path, str)
            or not isinstance(item, dict)
            or not isinstance(item.get("version"), str)
        ):
            raise ValueError("Invalid npm lockfile package entry")
        name = item.get("name") or path.rsplit("node_modules/", maxsplit=1)[-1]
        if not isinstance(name, str) or not name:
            raise ValueError(f"Invalid npm lockfile package name: {path}")
        scope = "dev" if item.get("dev") is True else "runtime or optional"
        if item.get("optional") is True:
            scope += ", optional"
        dependencies.append(
            {
                "ecosystem": "npm",
                "name": name,
                "version": item["version"],
                "lock_path": f"frontend/package-lock.json:{path}",
                "scope": scope,
            }
        )
    if not dependencies:
        raise ValueError("Source bundle lockfiles contain no packages")
    return sorted(
        dependencies, key=lambda item: (item["ecosystem"], item["name"], item.get("lock_path", ""))
    ), str(manifest.get("commit") or "")


def _package_id(prefix: str, value: str) -> str:
    return f"SPDXRef-{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:20]}"


def _declared_package(item: dict[str, str]) -> dict[str, object]:
    identity = json.dumps(item, sort_keys=True)
    package: dict[str, object] = {
        "SPDXID": _package_id("Dependency", identity),
        "name": item["name"],
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if "version" in item:
        package["versionInfo"] = item["version"]
        if item["ecosystem"] == "pypi" and item.get("source") == "pypi registry":
            purl = (
                f"pkg:pypi/{quote(item['name'].lower().replace('_', '-'))}@{quote(item['version'])}"
            )
        elif item["ecosystem"] == "npm":
            name = item["name"]
            if name.startswith("@") and "/" in name:
                namespace, local_name = name.split("/", maxsplit=1)
                purl = (
                    f"pkg:npm/{quote(namespace, safe='')}/{quote(local_name)}"
                    f"@{quote(item['version'])}"
                )
            else:
                purl = f"pkg:npm/{quote(name)}@{quote(item['version'])}"
        else:
            purl = None
        if purl is not None:
            package["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ]
        package["sourceInfo"] = (
            f"Referenced by {item['lock_path']}; not installed in the source archive."
        )
    else:
        package["sourceInfo"] = (
            "Declared in distribution Requires-Dist; resolution is environment-dependent."
        )
    package["comment"] = json.dumps(item, sort_keys=True)
    return package


def _spdx_document(
    name: str,
    version: str,
    artifact_sha256: str,
    records: list[dict[str, object]],
    dependencies: list[dict[str, str]],
    created: str,
    kind: str,
) -> dict[str, object]:
    root_id = "SPDXRef-ReleaseArtifact"
    files = []
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": root_id,
            "relationshipType": "DESCRIBES",
        }
    ]
    for record in records:
        file_id = _package_id("File", str(record["name"]))
        files.append(
            {
                "SPDXID": file_id,
                "fileName": f"./{record['name']}",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": record["sha1"]},
                    {"algorithm": "SHA256", "checksumValue": record["sha256"]},
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relatedSpdxElement": file_id,
                "relationshipType": "CONTAINS",
            }
        )
    package = {
        "SPDXID": root_id,
        "name": PROJECT if kind != "local_source_zip" else f"{PROJECT}-local-source-bundle",
        "versionInfo": version,
        "packageFileName": name,
        "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_sha256}],
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "packageVerificationCode": {
            "packageVerificationCodeValue": hashlib.sha1(
                "".join(sorted(str(record["sha1"]) for record in records)).encode()
            ).hexdigest()
        },
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "sourceInfo": "Exact files and checksums were read from the built release archive.",
    }
    packages: list[dict[str, object]] = [package]
    for dependency in dependencies:
        declared = _declared_package(dependency)
        packages.append(declared)
        relationship = {
            "spdxElementId": root_id,
            "relatedSpdxElement": declared["SPDXID"],
            "relationshipType": "DEPENDS_ON" if "requirement" in dependency else "OTHER",
            "comment": (
                "Declared Requires-Dist only; not a statement that this version is installed."
                if "requirement" in dependency
                else "Referenced by an archived lockfile; not installed in this source archive."
            ),
        }
        relationships.append(relationship)
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-artifact-inventory",
        "documentNamespace": f"{REPOSITORY}/sbom/{artifact_sha256}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: build_release_artifact_evidence.py"],
            "comment": (
                "Timestamp records evidence generation time. Artifact files were hashed "
                "from the archive; "
                "dependency packages are declared or locked references, not installed files."
            ),
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }


def _select_artifacts(dist: Path) -> list[tuple[Path, str, str]]:
    matches = []
    for pattern, kind in (
        ("*.whl", "wheel"),
        ("*.tar.gz", "sdist"),
        ("*-local-*.zip", "local_source_zip"),
    ):
        found = sorted(dist.glob(pattern))
        if len(found) != 1 or not found[0].is_file() or found[0].is_symlink():
            raise ValueError(
                f"Expected exactly one regular {pattern} in {dist}; found {len(found)}"
            )
        path = found[0]
        if kind == "wheel":
            match = re.fullmatch(r"vuln_prioritizer_workbench-([^-]+)-.+\.whl", path.name)
        elif kind == "sdist":
            match = re.fullmatch(r"vuln_prioritizer_workbench-([^-]+)\.tar\.gz", path.name)
        else:
            match = re.fullmatch(r"vuln-prioritizer-workbench-local-(.+)\.zip", path.name)
        if match is None:
            raise ValueError(f"Unexpected release artifact filename: {path.name}")
        matches.append((path, kind, match.group(1)))
    versions = {version for _path, _kind, version in matches}
    if len(versions) != 1:
        raise ValueError(f"Release artifact versions differ: {sorted(versions)}")
    return matches


def _source_commit(explicit: str | None) -> str:
    commit = explicit or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if COMMIT.fullmatch(commit) is None:
        raise ValueError("Source commit must be a full Git SHA")
    return commit


def _created_timestamp(explicit: str | None) -> str:
    if explicit:
        moment = datetime.fromisoformat(explicit.replace("Z", "+00:00"))
    elif "SOURCE_DATE_EPOCH" in os.environ:
        moment = datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]), UTC)
    else:
        moment = datetime.now(UTC)
    if moment.tzinfo is None:
        raise ValueError("Evidence timestamp requires a timezone")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _analyze(
    path: Path, kind: str, version: str, created: str, commit: str
) -> tuple[dict[str, object], dict[str, object]]:
    artifact_sha256 = _hash_file(path)
    if kind == "sdist":
        records, selected = _read_sdist(path)
        dependencies = _metadata_dependencies(_single_metadata(selected, "/PKG-INFO"), version)
    else:
        records, selected = _read_zip(path)
        if kind == "wheel":
            dependencies = _metadata_dependencies(
                _single_metadata(selected, ".dist-info/METADATA"), version
            )
        else:
            dependencies, bundle_commit = _bundle_dependencies(selected, version)
            if bundle_commit != commit:
                raise ValueError(
                    "Bundle manifest source commit differs from evidence source commit"
                )
            manifest = json.loads(_single_metadata(selected, "/BUNDLE-MANIFEST.json"))
            prefix = f"vuln-prioritizer-workbench-local-{version}/"
            expected = {prefix + item["path"]: item for item in manifest["files"]}
            actual = {
                str(item["name"]): item
                for item in records
                if not str(item["name"]).endswith("/BUNDLE-MANIFEST.json")
            }
            if expected.keys() != actual.keys() or manifest.get("file_count") != len(expected):
                raise ValueError("Bundle manifest does not describe exactly the archive files")
            if any(
                actual[name]["sha256"] != item["sha256"] or actual[name]["size"] != item["size"]
                for name, item in expected.items()
            ):
                raise ValueError("Bundle manifest file checksum/size mismatch")
    if not records:
        raise ValueError(f"Release artifact is empty: {path.name}")
    if _hash_file(path) != artifact_sha256:
        raise ValueError(f"Release artifact changed while being cataloged: {path.name}")
    sbom = _spdx_document(path.name, version, artifact_sha256, records, dependencies, created, kind)
    subject = {
        "name": path.name,
        "kind": kind,
        "version": version,
        "sha256": artifact_sha256,
        "size": path.stat().st_size,
        "archive_file_count": len(records),
        "dependency_reference_count": len(dependencies),
        "sbom": f"{path.name}.spdx.json",
        "sbom_sha256": hashlib.sha256(_json_bytes(sbom)).hexdigest(),
    }
    return sbom, subject


def _build(args: argparse.Namespace) -> None:
    artifacts = _select_artifacts(args.dist)
    commit = _source_commit(args.commit)
    created = _created_timestamp(args.created)
    build_inputs = None
    build_inputs_bytes = None
    if args.build_inputs is not None:
        build_inputs_bytes = args.build_inputs.read_bytes()
        bundle = next(path for path, kind, _version in artifacts if kind == "local_source_zip")
        _validate_build_inputs(build_inputs_bytes, bundle, commit, args.ref, args.run_url)
        build_inputs = {
            "filename": "build-inputs.json",
            "sha256": hashlib.sha256(build_inputs_bytes).hexdigest(),
        }
    sboms: dict[str, bytes] = {}
    subjects = []
    for path, kind, version in artifacts:
        sbom, subject = _analyze(path, kind, version, created, commit)
        sboms[str(subject["sbom"])] = _json_bytes(sbom)
        subjects.append(subject)
    provenance = {
        "schema_version": SCHEMA,
        "created": created,
        "source": {"repository": REPOSITORY, "commit": commit, "ref": args.ref},
        "build": {
            "workflow_run_url": args.run_url,
            "claim": "self-reported build context; unsigned",
            "inputs": build_inputs,
        },
        "subjects": subjects,
        "verification_scope": (
            "Local verification recomputes archive and SBOM bytes, package metadata, and "
            "lockfile references. It does not authenticate the claimed builder or source commit."
        ),
    }
    args.output.mkdir(parents=True, exist_ok=True)
    for filename, data in sboms.items():
        (args.output / filename).write_bytes(data)
    if build_inputs_bytes is not None:
        (args.output / "build-inputs.json").write_bytes(build_inputs_bytes)
    (args.output / "release-artifact-evidence.json").write_bytes(_json_bytes(provenance))
    print(args.output / "release-artifact-evidence.json")


def _verify(args: argparse.Namespace) -> None:
    provenance = json.loads((args.output / "release-artifact-evidence.json").read_text())
    if provenance.get("schema_version") != SCHEMA:
        raise ValueError("Unsupported release evidence schema")
    commit = provenance["source"]["commit"]
    if COMMIT.fullmatch(commit) is None or provenance["source"].get("repository") != REPOSITORY:
        raise ValueError("Invalid release evidence source")
    build_inputs = provenance["build"].get("inputs")
    if build_inputs is not None:
        if build_inputs.get("filename") != "build-inputs.json" or not HEX_SHA256.fullmatch(
            build_inputs.get("sha256", "")
        ):
            raise ValueError("Invalid build-inputs reference")
        build_input_bytes = (args.output / "build-inputs.json").read_bytes()
        if hashlib.sha256(build_input_bytes).hexdigest() != build_inputs["sha256"]:
            raise ValueError("Build-inputs checksum mismatch")
    artifacts = _select_artifacts(args.dist)
    if build_inputs is not None:
        bundle = next(path for path, kind, _version in artifacts if kind == "local_source_zip")
        _validate_build_inputs(
            build_input_bytes,
            bundle,
            commit,
            provenance["source"].get("ref"),
            provenance["build"].get("workflow_run_url"),
        )
    actual_subjects = []
    recorded = {item["name"]: item for item in provenance["subjects"]}
    if len(recorded) != 3:
        raise ValueError("Release evidence must describe exactly three artifacts")
    for path, kind, version in artifacts:
        sbom, subject = _analyze(path, kind, version, provenance["created"], commit)
        if recorded.get(path.name) != subject:
            raise ValueError(f"Artifact evidence mismatch: {path.name}")
        if (args.output / str(subject["sbom"])).read_bytes() != _json_bytes(sbom):
            raise ValueError(f"SPDX inventory mismatch: {path.name}")
        actual_subjects.append(subject)
    if provenance["subjects"] != actual_subjects:
        raise ValueError("Release evidence subject order/content mismatch")
    expected_files = {"release-artifact-evidence.json"}
    expected_files.update(str(subject["sbom"]) for subject in actual_subjects)
    if build_inputs is not None:
        expected_files.add("build-inputs.json")
    entries = list(args.output.iterdir())
    if any(not entry.is_file() or entry.is_symlink() for entry in entries):
        raise ValueError("Release evidence output contains a non-regular file")
    if {entry.name for entry in entries} != expected_files:
        raise ValueError("Release evidence output contains missing or stale files")
    print(f"{args.output / 'release-artifact-evidence.json'}: verified")


def main() -> int:
    """Build or verify evidence for one version's wheel, sdist, and local ZIP."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("build/release-artifact-evidence"))
    parser.add_argument("--commit", help="Full Git SHA of the release checkout (build only).")
    parser.add_argument("--ref", help="Release ref, e.g. refs/tags/v1.3.0 (build only).")
    parser.add_argument("--run-url", help="CI workflow run URL (build only).")
    parser.add_argument(
        "--build-inputs",
        type=Path,
        help="JSON file recording toolchain/lock context; copied and hashed into evidence.",
    )
    parser.add_argument(
        "--created", help="UTC ISO-8601 creation time; defaults to SOURCE_DATE_EPOCH or now."
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Independently re-read artifacts and validate stored evidence.",
    )
    args = parser.parse_args()
    try:
        if args.verify:
            _verify(args)
        else:
            _build(args)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        tarfile.TarError,
        zipfile.BadZipFile,
        subprocess.CalledProcessError,
    ) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
