#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <docker-compose-args...> -- <service...>" >&2
}

if [[ "$#" -lt 3 ]]; then
  usage
  exit 64
fi

attempts="${VPW_DOCKER_PULL_ATTEMPTS:-3}"
delay_seconds="${VPW_DOCKER_PULL_RETRY_DELAY_SECONDS:-10}"
if ! [[ "$attempts" =~ ^[1-9][0-9]*$ ]]; then
  echo "VPW_DOCKER_PULL_ATTEMPTS must be a positive integer." >&2
  exit 64
fi
if ! [[ "$delay_seconds" =~ ^[0-9]+$ ]]; then
  echo "VPW_DOCKER_PULL_RETRY_DELAY_SECONDS must be a non-negative integer." >&2
  exit 64
fi

compose_args=()
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--" ]]; then
    shift
    break
  fi
  compose_args+=("$1")
  shift
done

if [[ "$#" -eq 0 ]]; then
  usage
  exit 64
fi
services=("$@")

for attempt in $(seq 1 "$attempts"); do
  if docker compose "${compose_args[@]}" pull "${services[@]}"; then
    exit 0
  fi
  status="$?"
  if [[ "$attempt" == "$attempts" ]]; then
    echo "docker compose pull failed after ${attempts} attempts." >&2
    exit "$status"
  fi
  echo "docker compose pull failed (attempt ${attempt}/${attempts}); retrying in ${delay_seconds}s." >&2
  sleep "$delay_seconds"
done
