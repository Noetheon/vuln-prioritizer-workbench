#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"

echo "scripts/start-template-playwright-backend.sh is deprecated; use scripts/start-workbench-playwright-backend.sh." >&2
if [[ -n "${TEMPLATE_PLAYWRIGHT_DB:-}" && -z "${WORKBENCH_PLAYWRIGHT_DB:-}" ]]; then
  export WORKBENCH_PLAYWRIGHT_DB="$TEMPLATE_PLAYWRIGHT_DB"
fi
if [[ -n "${TEMPLATE_PLAYWRIGHT_REPORT_DIR:-}" && -z "${WORKBENCH_PLAYWRIGHT_REPORT_DIR:-}" ]]; then
  export WORKBENCH_PLAYWRIGHT_REPORT_DIR="$TEMPLATE_PLAYWRIGHT_REPORT_DIR"
fi

exec bash "$repo_root/scripts/start-workbench-playwright-backend.sh"
