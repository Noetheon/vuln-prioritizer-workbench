#!/usr/bin/env bash
set -euo pipefail

mode="${1:-verify}"
case "$mode" in
  verify)
    npm_script="test:design-audit"
    ;;
  update)
    npm_script="test:design-audit:update"
    ;;
  *)
    echo "Usage: $0 [verify|update]" >&2
    exit 64
    ;;
esac

if [[ "${DOCKER_DEFAULT_PLATFORM:-}" == "linux/amd64" && "${ALLOW_EMULATED_PLAYWRIGHT:-}" != "1" ]]; then
  echo "Refusing DOCKER_DEFAULT_PLATFORM=linux/amd64 for the visual audit." >&2
  echo "Unset DOCKER_DEFAULT_PLATFORM to use Docker's native platform selection on Apple Silicon." >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host_arch="$(uname -m)"
docker_server_arch="$(docker version --format '{{.Server.Arch}}')"
docker_server_os="$(docker version --format '{{.Server.Os}}')"
playwright_image="${PLAYWRIGHT_DOCKER_IMAGE:-mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948}"

node_modules_volume="${PLAYWRIGHT_NODE_MODULES_VOLUME:-vpw_frontend_node_modules_${docker_server_os}_${docker_server_arch}}"
npm_cache_volume="${PLAYWRIGHT_NPM_CACHE_VOLUME:-vpw_npm_cache_${docker_server_os}_${docker_server_arch}}"
pip_cache_volume="${PLAYWRIGHT_PIP_CACHE_VOLUME:-vpw_pip_cache_${docker_server_os}_${docker_server_arch}}"

echo "host-arch=${host_arch} docker-server=${docker_server_os}/${docker_server_arch}"
echo "playwright-image=${playwright_image}"

docker run --rm \
  --ipc=host \
  --shm-size=2g \
  -e HOST_ARCH="${host_arch}" \
  -e HOST_GID="$(id -g)" \
  -e HOST_UID="$(id -u)" \
  -e VPW_DESIGN_AUDIT_ROUTE="${VPW_DESIGN_AUDIT_ROUTE:-}" \
  -v "${repo_root}:/work" \
  -v "${node_modules_volume}:/work/frontend/node_modules" \
  -v "${npm_cache_volume}:/root/.npm" \
  -v "${pip_cache_volume}:/root/.cache/pip" \
  -w /work \
  "${playwright_image}" \
  bash -lc '
    set -euo pipefail
    cleanup_ownership() {
      status=$?
      if [[ -n "${HOST_UID:-}" && -n "${HOST_GID:-}" ]]; then
        if [[ -d /work/build ]]; then
          chown "${HOST_UID}:${HOST_GID}" /work/build 2>/dev/null || true
        fi
        for artifact_path in \
          /work/build/frontend-playwright-workbench-*.db \
          /work/build/frontend-playwright-workbench-*-reports \
          /work/frontend/test-results \
          /work/frontend/playwright-report \
          /work/frontend/blob-report; do
          if [[ -e "${artifact_path}" ]]; then
            chown -R "${HOST_UID}:${HOST_GID}" "${artifact_path}" 2>/dev/null || true
          fi
        done
      fi
      exit "$status"
    }
    trap cleanup_ownership EXIT

    container_arch="$(uname -m)"
    echo "container-arch=${container_arch}"

    if [[ "${HOST_ARCH}" == "arm64" || "${HOST_ARCH}" == "aarch64" ]]; then
      if [[ "${container_arch}" != "arm64" && "${container_arch}" != "aarch64" && "${ALLOW_EMULATED_PLAYWRIGHT:-}" != "1" ]]; then
        echo "Expected native ARM container on Apple Silicon, got ${container_arch}." >&2
        exit 64
      fi
    fi

    git config --global --add safe.directory /work

    if ! command -v pip3 >/dev/null 2>&1; then
      apt-get update >/dev/null
      apt-get install -y python3-pip >/dev/null
    fi

    python3 -m pip install --break-system-packages -e "backend"
    cd frontend
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm_config_engine_strict=false npm ci --workspaces=false --no-audit --no-fund --prefer-offline
    npm_config_engine_strict=false npm run '"${npm_script}"'
  '
