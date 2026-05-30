#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
required_node_major="22"
required_npm_major="10"
required_npm_version="10.9.4"

run_npm() {
  local npm_bin="$1"
  shift
  "$npm_bin" "$@"
}

node_major() {
  node -p 'process.versions.node.split(".")[0]'
}

npm_major() {
  npm -v | cut -d. -f1
}

if command -v volta >/dev/null 2>&1; then
  cd "$repo_root"
  exec volta run npm "$@"
fi

if command -v mise >/dev/null 2>&1; then
  cd "$repo_root"
  exec mise exec node@"$required_node_major" -- npm "$@"
fi

if command -v asdf >/dev/null 2>&1; then
  cd "$repo_root"
  exec asdf exec npm "$@"
fi

if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  # shellcheck source=/dev/null
  source "$HOME/.nvm/nvm.sh"
  nvm install "$required_node_major" >/dev/null
  nvm use "$required_node_major" >/dev/null
  current_npm="$(npm -v)"
  if [[ "$(npm_major)" != "$required_npm_major" ]]; then
    npm install -g "npm@$required_npm_version" >/dev/null
  fi
  cd "$repo_root"
  run_npm npm "$@"
  exit $?
fi

if [[ "${FRONTEND_ALLOW_UNPINNED_NODE:-}" == "1" ]]; then
  cd "$repo_root"
  exec npm "$@"
fi

if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  if [[ "$(node_major)" == "$required_node_major" && "$(npm_major)" == "$required_npm_major" ]]; then
    cd "$repo_root"
    exec npm "$@"
  fi
fi

{
  echo "frontend toolchain mismatch"
  echo "required: Node ${required_node_major}.x with npm ${required_npm_major}.x"
  if command -v node >/dev/null 2>&1; then
    echo "current node: $(node -v)"
  else
    echo "current node: not found"
  fi
  if command -v npm >/dev/null 2>&1; then
    echo "current npm: $(npm -v)"
  else
    echo "current npm: not found"
  fi
  echo "Install Volta or mise, then rerun the make target."
  echo "Temporary override for diagnostics only: FRONTEND_ALLOW_UNPINNED_NODE=1"
} >&2
exit 1
