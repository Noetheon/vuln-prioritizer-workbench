#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"
if [[ "$#" -eq 0 ]]; then
  set -- start
fi
exec bash scripts/launch-workbench.sh "$@"
