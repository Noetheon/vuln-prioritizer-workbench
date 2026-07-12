# Single-Process Runtime Transition

This is the operator runbook for moving from the deprecated Docker
Compose/PostgreSQL topology to the standard `vpw serve` runtime. New
installations should start directly with `vpw serve` and do not need this
procedure.

## Runtime Contract

The standard runtime contains one FastAPI process with:

- the packaged same-origin React application;
- the existing `/api/v1` API and generated-client contract;
- a supervised in-process Workflow v2 worker;
- one SQLite database configured with foreign keys, a 30-second busy timeout,
  WAL journaling, normal synchronous durability, and periodic checkpoints;
- private local directories for uploads, reports, provider snapshots, and the
  provider cache.

The workflow queue remains database-backed. Imports, provider refreshes, and
reports keep their leases, retries, cancellation, events, and persisted state;
only the worker deployment shape changes.

## Before Migrating

1. Upgrade the Compose compatibility stack to the same candidate that provides
   `vpw migrate database`. Let its backend apply Alembic head
   `20260710_0004`.
2. Close the browser and wait until every workflow is terminal. Do not migrate
   while imports, provider refreshes, or reports are running.
3. Keep the PostgreSQL volume. Do not run `docker compose down -v` or the
   destructive launcher reset.
4. Choose a new, empty target directory outside the repository, for example
   `./vpw-data-migrated`.

## Create A Quiescent Backup

Stop the UI and worker first, leave the backend and database available, and
create the existing database plus artifact backup:

```bash
docker compose -f compose.yml -f compose.override.yml stop frontend worker
BACKUP_DIR=./backups/pre-vpw-serve \
WORKBENCH_DATABASE_MODE=compose \
WORKBENCH_ARTIFACT_MODE=compose \
scripts/workbench-backup.sh
docker compose -f compose.yml -f compose.override.yml stop backend
```

With the browser closed and the worker stopped, the remaining backend must not
receive API writes during this window. The `db` service stays running so the
verified migration can read a consistent PostgreSQL snapshot. Keep
`workbench.dump` as the rollback backup even though the migration command reads
the live, quiescent database.

## Run The Verified Migration

The backend image already contains the new `vpw` command and PostgreSQL driver.
On macOS or Linux, run it as a one-off container on the existing Compose
network:

```bash
mkdir -p ./vpw-data-migrated
docker compose -f compose.yml -f compose.override.yml run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/vpw-data-migrated:/migration" \
  -v "$PWD/backups/pre-vpw-serve:/backup:ro" \
  backend \
  vpw migrate database \
    --source-postgres-env \
    --data-dir /migration \
    --artifact-archive /backup/artifacts.tar
```

For a host-reachable PostgreSQL source, use an environment variable instead of
putting credentials in shell history:

```bash
export VPW_SOURCE_DATABASE_URL='postgresql+psycopg://...'
vpw migrate database \
  --data-dir ./vpw-data-migrated \
  --artifact-archive ./backups/pre-vpw-serve/artifacts.tar
unset VPW_SOURCE_DATABASE_URL
```

The command refuses a non-empty target and never prints the source URL. It:

1. requires source and target to be at the same Alembic head;
2. verifies complete source Decision Ledger coverage and parity;
3. copies every application table in a consistent source transaction;
4. compares row counts and canonical SHA-256 digests table by table;
5. rewrites only server-owned report paths to their deterministic new root;
6. rejects unsafe archive paths, links, duplicates, and unknown roots;
7. verifies referenced upload and report files against persisted size and
   SHA-256 metadata;
8. checks SQLite foreign keys and complete target Ledger parity;
9. activates `workbench.db` only after all checks pass.

If any check fails, no target database is activated and the PostgreSQL source
is unchanged.

## Validate And Switch

Install the same candidate on the host, verify the complete Ledger again, and
start the migrated instance:

```bash
pipx install ./vuln_prioritizer_workbench-X.Y.Z-py3-none-any.whl
vpw ledger verify --strict --data-dir ./vpw-data-migrated
vpw serve --data-dir ./vpw-data-migrated
```

Check at least:

- project, run, finding, waiver, asset, provider, and report counts;
- finding order and filters;
- one historical run and one current finding detail;
- download and verification of an existing report/evidence bundle;
- one new import and one new report after the migration;
- a clean stop and restart with the new state still present.

Keep the Compose services stopped but retain their volumes and backup through
the transition release.

## Rollback

Stop `vpw serve`, preserve the failed/new data directory for diagnosis, and
restart the untouched compatibility services:

```bash
docker compose -f compose.yml -f compose.override.yml start db backend worker frontend
```

If the source itself must be restored, use the verified `workbench.dump` and
artifact archive with `scripts/workbench-restore.sh`. Never restore a PostgreSQL
dump over the SQLite file or copy only `workbench.db` while its process is
running.

## Compose Removal Gate

Compose/PostgreSQL may be removed only after one released transition cycle and
fresh evidence for the exact removal candidate proves:

- API, import, workflow, report, provider, and Decision Ledger contract tests
  on SQLite and PostgreSQL;
- exact database-copy count/digest parity plus artifact verification on a
  representative non-empty fixture;
- crash, worker-restart, process-restart, and SQLite locking behavior;
- package-installed same-origin browser smoke on every supported platform;
- a documented backup and rollback rehearsal;
- no unresolved migration-loss or single-process regression from the
  transition release.

Until every gate is recorded, Compose remains deprecated but supported. Its
continued presence is a rollback boundary, not a second product direction.
