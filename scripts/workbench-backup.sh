#!/usr/bin/env sh
set -eu

BACKUP_DIR="${BACKUP_DIR:-./backups/workbench-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$BACKUP_DIR"
DEFAULT_ARTIFACT_PATHS="data/workbench-import-uploads data/workbench-reports data/workbench-provider-cache data/provider-snapshots"
DEFAULT_COMPOSE_ARTIFACT_PATHS="workbench-import-uploads workbench-reports provider-snapshots workbench-provider-cache"

host_artifact_paths() {
  if [ -n "${WORKBENCH_ARTIFACT_PATHS:-}" ]; then
    printf '%s\n' "$WORKBENCH_ARTIFACT_PATHS"
    return
  fi
  printf '%s\n' "$DEFAULT_ARTIFACT_PATHS"
}

compose_artifact_paths() {
  printf '%s\n' "$DEFAULT_COMPOSE_ARTIFACT_PATHS"
}

backup_compose_database() {
  container="${WORKBENCH_DATABASE_CONTAINER:-}"
  if [ -z "$container" ]; then
    container="$(docker compose ps -q db 2>/dev/null || true)"
  fi
  if [ -z "$container" ]; then
    echo "Set WORKBENCH_DATABASE_CONTAINER or run from a started Docker Compose stack." >&2
    exit 2
  fi
  docker exec "$container" sh -c \
    ': "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set in the Compose db container.}"; PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --format=custom --file=- --username="${POSTGRES_USER:-workbench}" --dbname="${POSTGRES_DB:-workbench}"' \
    > "$BACKUP_DIR/workbench.dump"
}

if [ -n "${SQLITE_DATABASE_PATH:-}" ]; then
  cp "$SQLITE_DATABASE_PATH" "$BACKUP_DIR/workbench.db"
elif [ -n "${DATABASE_URL:-}" ]; then
  pg_dump --format=custom --file="$BACKUP_DIR/workbench.dump" "$DATABASE_URL"
elif [ "${WORKBENCH_DATABASE_MODE:-host}" = "compose" ]; then
  backup_compose_database
elif [ -n "${POSTGRES_SERVER:-}" ]; then
  PGHOST="${POSTGRES_SERVER:-${PGHOST:-localhost}}"
  PGPORT="${POSTGRES_PORT:-${PGPORT:-5432}}"
  PGDATABASE="${POSTGRES_DB:-${PGDATABASE:-workbench}}"
  PGUSER="${POSTGRES_USER:-${PGUSER:-workbench}}"
  export PGHOST PGPORT PGDATABASE PGUSER
  pg_dump --format=custom --file="$BACKUP_DIR/workbench.dump"
else
  echo "Set SQLITE_DATABASE_PATH, DATABASE_URL, WORKBENCH_DATABASE_MODE=compose, or Postgres PG*/POSTGRES_* environment variables." >&2
  exit 2
fi

backup_host_artifacts() {
  for path in $(host_artifact_paths); do
    if [ -e "$path" ]; then
      tar -C "$(dirname "$path")" -rf "$BACKUP_DIR/artifacts.tar" "$(basename "$path")"
    fi
  done
}

backup_compose_artifacts() {
  container="${WORKBENCH_BACKUP_CONTAINER:-}"
  if [ -z "$container" ]; then
    container="$(docker compose ps -q backend 2>/dev/null || true)"
  fi
  if [ -z "$container" ]; then
    echo "Set WORKBENCH_BACKUP_CONTAINER or run from a started Docker Compose stack." >&2
    exit 2
  fi
  artifact_paths="$(compose_artifact_paths)"
  docker exec "$container" sh -c \
    'existing=""; for path do [ -e "/app/$path" ] && existing="$existing $path"; done; if [ -n "$existing" ]; then tar -C /app -cf - $existing; else tar -C /tmp -cf - --files-from /dev/null; fi' \
    sh $artifact_paths \
    > "$BACKUP_DIR/artifacts.tar"
}

case "${WORKBENCH_ARTIFACT_MODE:-host}" in
  host) backup_host_artifacts ;;
  compose) backup_compose_artifacts ;;
  none) ;;
  *)
    echo "WORKBENCH_ARTIFACT_MODE must be host, compose, or none." >&2
    exit 2
    ;;
esac

printf '%s\n' "$BACKUP_DIR"
