#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="${VULN_PRIORITIZER_SMOKE_OUTPUT_DIR:-}"
if [[ -n "$TMP_DIR" ]]; then
  rm -rf "$TMP_DIR"
  mkdir -p "$TMP_DIR"
  CLEANUP_TMP_DIR=0
else
  TMP_DIR="$(mktemp -d)"
  CLEANUP_TMP_DIR=1
fi
trap '[[ "$CLEANUP_TMP_DIR" == "1" ]] && rm -rf "$TMP_DIR"' EXIT
PYTHON_BIN="${PYTHON_BIN:-python3}"

SOURCE_ROOT="$ROOT_DIR"
PIPX_SPEC="${VULN_PRIORITIZER_PIPX_SPEC:-}"

if [[ -z "$PIPX_SPEC" ]]; then
  REPO_COPY="$TMP_DIR/repo"
  mkdir -p "$REPO_COPY"
  tar \
    --exclude=.git \
    --exclude=.venv \
    --exclude=.mypy_cache \
    --exclude=.pytest_cache \
    --exclude=.ruff_cache \
    --exclude=.tox \
    --exclude=build \
    --exclude=dist \
    --exclude=site \
    -cf - \
    -C "$ROOT_DIR" . | tar -xf - -C "$REPO_COPY"

  SOURCE_ROOT="$REPO_COPY"
  PIPX_SPEC="$REPO_COPY"
fi

CLI=("$PYTHON_BIN" -m pipx run --spec "$PIPX_SPEC" vuln-prioritizer)
DOCTOR_OUTPUT="$TMP_DIR/doctor.json"

"${CLI[@]}" --help > /dev/null
"${CLI[@]}" doctor --format json --output "$DOCTOR_OUTPUT"

PYTHON_BIN="$PYTHON_BIN" \
VULN_PRIORITIZER_PIPX_SPEC="$PIPX_SPEC" \
bash "$SOURCE_ROOT/scripts/p1_installed_cli_smoke.sh"

PYTHON_BIN="$PYTHON_BIN" \
VULN_PRIORITIZER_PIPX_SPEC="$PIPX_SPEC" \
bash "$SOURCE_ROOT/scripts/p2_installed_cli_smoke.sh"
