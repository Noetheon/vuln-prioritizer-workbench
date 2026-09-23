#!/usr/bin/env sh
set -eu
umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BACKUP_DIR="${1:-${BACKUP_DIR:-}}"
if [ -z "$BACKUP_DIR" ] || [ ! -d "$BACKUP_DIR" ]; then
  echo "Usage: scripts/workbench-restore.sh <backup-dir>" >&2
  exit 2
fi
if [ -f "$BACKUP_DIR/backup-checksums.json" ]; then
  python3 "$SCRIPT_DIR/verify_backup_checksums.py" verify "$BACKUP_DIR"
else
  python3 "$SCRIPT_DIR/verify_backup_checksums.py" check-source "$BACKUP_DIR"
  echo "Legacy backup has no private SHA-256 checksum record." >&2
fi

restore_compose_database() {
  container="${WORKBENCH_DATABASE_CONTAINER:-}"
  if [ -z "$container" ]; then
    container="$(docker compose ps -q db 2>/dev/null || true)"
  fi
  if [ -z "$container" ]; then
    echo "Set WORKBENCH_DATABASE_CONTAINER or run from a started Docker Compose stack." >&2
    exit 2
  fi
  docker exec -i "$container" sh -c \
    ': "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set in the Compose db container.}"; PGPASSWORD="$POSTGRES_PASSWORD" pg_restore --clean --if-exists --username="${POSTGRES_USER:-workbench}" --dbname="${POSTGRES_DB:-workbench}" --exit-on-error --single-transaction' \
    < "$BACKUP_DIR/workbench.dump"
}

restore_host_artifacts() {
  ARTIFACT_RESTORE_ROOT="${ARTIFACT_RESTORE_ROOT:-${SQLITE_DATABASE_PATH:+$(dirname -- "$SQLITE_DATABASE_PATH")}}"
  ARTIFACT_RESTORE_ROOT="${ARTIFACT_RESTORE_ROOT:-.}"
  tar -C "$ARTIFACT_RESTORE_ROOT" -xf "$BACKUP_DIR/artifacts.tar"
}

restore_compose_artifacts() {
  container="${WORKBENCH_BACKUP_CONTAINER:-}"
  if [ -z "$container" ]; then
    container="$(docker compose ps -q backend 2>/dev/null || true)"
  fi
  if [ -z "$container" ]; then
    echo "Set WORKBENCH_BACKUP_CONTAINER or run from a started Docker Compose stack." >&2
    exit 2
  fi
  docker exec -i "$container" sh -c "tar -C /app -xf -" < "$BACKUP_DIR/artifacts.tar"
}

validate_artifact_archive() {
  archive="$1"
  if ! tar -tf "$archive" >/dev/null; then
    echo "Artifact archive is not a readable tar file: $archive" >&2
    exit 2
  fi

  bad_member="$(
    tar -tf "$archive" | awk '
      $0 == "" || $0 == "." || $0 ~ /^\// || $0 == ".." || $0 ~ /^\.\.\// || $0 ~ /\/\.\.(\/|$)/ {
        print
        exit
      }
    ' || true
  )"
  if [ -n "$bad_member" ]; then
    echo "Refusing artifact archive with unsafe member path: $bad_member" >&2
    exit 2
  fi

  bad_link="$(
    tar -tvf "$archive" | awk '
      substr($0, 1, 1) == "l" || substr($0, 1, 1) == "h" {
        print
        exit
      }
    ' || true
  )"
  if [ -n "$bad_link" ]; then
    echo "Refusing artifact archive with symlink or hardlink member: $bad_link" >&2
    exit 2
  fi
}

artifact_mode="${WORKBENCH_ARTIFACT_MODE:-host}"
case "$artifact_mode" in
  host|compose|none) ;;
  *)
    echo "WORKBENCH_ARTIFACT_MODE must be host, compose, or none." >&2
    exit 2
    ;;
esac
if [ -f "$BACKUP_DIR/artifacts.tar" ] && [ "$artifact_mode" != "none" ]; then
  validate_artifact_archive "$BACKUP_DIR/artifacts.tar"
fi

artifacts_restored=0
if [ -n "${SQLITE_DATABASE_PATH:-}" ] && [ -f "$BACKUP_DIR/workbench.db" ]; then
  if [ "$artifact_mode" = "compose" ]; then
    echo "SQLite restore requires host or none artifact mode." >&2
    exit 2
  fi
  # Prepare a private copy first. Every database report reference must match a
  # regular archived report with its recorded size and SHA-256 before the live
  # SQLite destination is replaced. Rebase absolute paths for a relocated root.
  restore_staging="$(mktemp -d)"
  trap 'rm -rf -- "$restore_staging"' EXIT HUP INT TERM
  report_root="${ARTIFACT_RESTORE_ROOT:-$(dirname -- "$SQLITE_DATABASE_PATH")}"
  set -- "$BACKUP_DIR/workbench.db" "$report_root" "$restore_staging/prepared.db"
  if [ -f "$BACKUP_DIR/artifacts.tar" ] && [ "$artifact_mode" != "none" ]; then
    set -- "$@" --archive "$BACKUP_DIR/artifacts.tar"
  fi
  if [ -f "$BACKUP_DIR/backup-manifest.json" ]; then
    set -- "$@" --manifest "$BACKUP_DIR/backup-manifest.json"
  fi
  python3 "$SCRIPT_DIR/restore_report_paths.py" prepare "$@"
  # A fresh root makes extraction failure unable to leave a new database with
  # missing artifacts. Extraction completes before the SQLite rename activates
  # the prepared database. Operators must preserve any existing root separately.
  python3 - "$report_root" "$SQLITE_DATABASE_PATH" <<'PY'
import sys
from pathlib import Path

requested_root = Path(sys.argv[1]).expanduser()
if requested_root.is_symlink():
    raise SystemExit("SQLite artifact restore root must not be a symlink.")
root = requested_root.resolve(strict=False)
database = Path(sys.argv[2]).expanduser().resolve(strict=False)
if database.parent != root:
    raise SystemExit("SQLite database and artifact restore root must be the same directory.")
root.mkdir(mode=0o700, parents=True, exist_ok=True)
if any(root.iterdir()):
    raise SystemExit("SQLite restore target must be a new or empty data directory.")
root.chmod(0o700)
PY
  if [ -f "$BACKUP_DIR/artifacts.tar" ] && [ "$artifact_mode" = "host" ]; then
    tar -C "$report_root" -xf "$BACKUP_DIR/artifacts.tar"
    artifacts_restored=1
  fi
  python3 "$SCRIPT_DIR/sqlite_backup.py" \
    restore "$restore_staging/prepared.db" "$SQLITE_DATABASE_PATH"
elif [ -n "${DATABASE_URL:-}" ] && [ -f "$BACKUP_DIR/workbench.dump" ]; then
  pg_restore --clean --if-exists --dbname="$DATABASE_URL" --exit-on-error --single-transaction "$BACKUP_DIR/workbench.dump"
elif [ "${WORKBENCH_DATABASE_MODE:-host}" = "compose" ] && [ -f "$BACKUP_DIR/workbench.dump" ]; then
  restore_compose_database
elif [ -f "$BACKUP_DIR/workbench.dump" ]; then
  PGHOST="${POSTGRES_SERVER:-${PGHOST:-localhost}}"
  PGPORT="${POSTGRES_PORT:-${PGPORT:-5432}}"
  PGDATABASE="${POSTGRES_DB:-${PGDATABASE:-workbench}}"
  PGUSER="${POSTGRES_USER:-${PGUSER:-workbench}}"
  export PGHOST PGPORT PGDATABASE PGUSER
  pg_restore --clean --if-exists --dbname="$PGDATABASE" --exit-on-error --single-transaction "$BACKUP_DIR/workbench.dump"
else
  echo "No compatible database backup found in $BACKUP_DIR." >&2
  exit 2
fi

if [ -f "$BACKUP_DIR/artifacts.tar" ] && [ "$artifacts_restored" -eq 0 ]; then
  case "$artifact_mode" in
    host) restore_host_artifacts ;;
    compose) restore_compose_artifacts ;;
    none) ;;
  esac
fi

printf 'restored %s\n' "$BACKUP_DIR"
