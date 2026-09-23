#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-./backups/workbench-$(date -u +%Y%m%dT%H%M%SZ)}"
# Backups contain database rows and uploaded artifacts. Create a new private
# destination so an existing directory, file, or symlink cannot be overwritten.
umask 077
mkdir -p -- "$(dirname -- "$BACKUP_DIR")"
if ! mkdir -m 700 -- "$BACKUP_DIR"; then
  echo "Backup destination must be a new directory: $BACKUP_DIR" >&2
  exit 2
fi
DEFAULT_ARTIFACT_PATHS="data/workbench-import-uploads data/workbench-reports data/workbench-provider-cache data/provider-snapshots"
DEFAULT_COMPOSE_ARTIFACT_PATHS="workbench-import-uploads workbench-reports provider-snapshots workbench-provider-cache"

host_artifact_paths() {
  if [ -n "${WORKBENCH_ARTIFACT_ROOT:-}" ]; then
    printf '%s\n' \
      "$WORKBENCH_ARTIFACT_ROOT/imports" \
      "$WORKBENCH_ARTIFACT_ROOT/reports" \
      "$WORKBENCH_ARTIFACT_ROOT/provider-cache" \
      "$WORKBENCH_ARTIFACT_ROOT/provider-snapshots"
    return
  fi
  if [ -n "${WORKBENCH_ARTIFACT_PATHS:-}" ]; then
    for path in $WORKBENCH_ARTIFACT_PATHS; do
      printf '%s\n' "$path"
    done
    return
  fi
  if [ -n "${SQLITE_DATABASE_PATH:-}" ]; then
    sqlite_root="$(dirname -- "$SQLITE_DATABASE_PATH")"
    printf '%s\n' \
      "$sqlite_root/imports" \
      "$sqlite_root/reports" \
      "$sqlite_root/provider-cache" \
      "$sqlite_root/provider-snapshots"
    return
  fi
  for path in $DEFAULT_ARTIFACT_PATHS; do
    printf '%s\n' "$path"
  done
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
  python3 "$SCRIPT_DIR/sqlite_backup.py" \
    backup "$SQLITE_DATABASE_PATH" "$BACKUP_DIR/workbench.db"
  report_root="${WORKBENCH_REPORT_ROOT:-}"
  upload_root="${WORKBENCH_UPLOAD_ROOT:-}"
  if [ -n "${WORKBENCH_ARTIFACT_PATHS:-}" ]; then
    for path in $WORKBENCH_ARTIFACT_PATHS; do
      case "$(basename -- "$path")" in
        reports|workbench-reports) report_root="${report_root:-$path}" ;;
        imports|workbench-import-uploads) upload_root="${upload_root:-$path}" ;;
      esac
    done
  else
    artifact_root="${WORKBENCH_ARTIFACT_ROOT:-$(dirname -- "$SQLITE_DATABASE_PATH")}"
    report_root="${report_root:-$artifact_root/reports}"
    upload_root="${upload_root:-$artifact_root/imports}"
  fi
  if [ -n "$report_root" ]; then
    python3 "$SCRIPT_DIR/restore_report_paths.py" manifest \
      "$report_root" "$BACKUP_DIR/backup-manifest.json" \
      --upload-root "${upload_root:-$(dirname -- "$report_root")/imports}"
  fi
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
host_artifact_paths | while IFS= read -r path; do
    if [ -e "$path" ]; then
      python3 "$SCRIPT_DIR/archive_workbench_artifacts.py" \
        "$BACKUP_DIR/artifacts.tar" "$path"
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

python3 "$SCRIPT_DIR/verify_backup_checksums.py" create "$BACKUP_DIR"
printf '%s\n' "$BACKUP_DIR"
