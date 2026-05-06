#!/usr/bin/env sh
set -eu

BACKUP_DIR="${BACKUP_DIR:-./backups/workbench-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$BACKUP_DIR"

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
    'PGPASSWORD="${POSTGRES_PASSWORD:-workbench}" pg_dump --format=custom --file=- --username="${POSTGRES_USER:-workbench}" --dbname="${POSTGRES_DB:-workbench}"' \
    > "$BACKUP_DIR/workbench.dump"
}

if [ -n "${SQLITE_DATABASE_PATH:-}" ]; then
  cp "$SQLITE_DATABASE_PATH" "$BACKUP_DIR/template.db"
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
  for path in ${WORKBENCH_ARTIFACT_PATHS:-data/template-import-uploads data/template-reports data/template-provider-cache data/provider-snapshots}; do
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
  docker exec "$container" sh -c \
    "tar -C /app -cf - template-import-uploads template-reports provider-snapshots template-provider-cache" \
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
