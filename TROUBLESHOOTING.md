# Troubleshooting

This guide starts with the standard `vpw serve` runtime. Docker Compose notes
apply only to the deprecated compatibility path.

## Command Not Found

Confirm the isolated package is installed and that the pipx binary directory is
on `PATH`:

```bash
pipx list
pipx ensurepath
vpw --version
```

Open a new terminal after `pipx ensurepath`. From a source checkout, reinstall
the current package with `pipx install --force ./backend`.

## Port Already In Use

Choose another loopback port:

```bash
vpw serve --port 8877
```

The browser URL then becomes `http://127.0.0.1:8877`.

## Browser Does Not Open

Start without browser automation and open the printed URL manually:

```bash
vpw serve --no-browser
```

Check `http://127.0.0.1:8765/api/v1/utils/health-check/`. A JSON response with
HTTP 200 proves the API is ready even when the operating system blocks automatic
browser launch.

## Database Or Migration Error

Stop VPW before inspecting or copying its data directory. Make a complete copy
of `workbench.db` plus any `workbench.db-wal` and `workbench.db-shm` files before
attempting recovery.

Then run the explicit ledger checks:

```bash
vpw ledger backfill --data-dir ./vpw-data
vpw ledger verify --strict --data-dir ./vpw-data
```

Use the same `--data-dir` that was passed to `vpw serve`. Do not delete a
database to work around a migration failure unless its contents are known to be
disposable.

## Work Remains Pending

Workflow state is durable in SQLite. Restart `vpw serve`; the supervised worker
will resume claimable jobs and expired leases according to the existing retry
contract. A worker exception is logged and the supervisor starts a replacement
worker after a bounded backoff.

If a workflow remains stuck, inspect its state in the Imports, Providers, or
Reports view. Preserve the data directory before resetting anything.

## Data Directory Permissions

The process must be able to create the data directory, SQLite database,
imports, reports, and provider-cache directories. Prefer a user-owned local
path:

```bash
mkdir -p "$HOME/vpw-data"
vpw serve --data-dir "$HOME/vpw-data"
```

Avoid network filesystems for the SQLite WAL database. They can violate SQLite
locking assumptions.

## Package Assets Missing

If VPW reports that packaged frontend assets are missing, reinstall the wheel:

```bash
pipx install --force ./backend
```

For a released candidate, replace `./backend` with the verified wheel path.

Repository developers must run the frontend build and runtime-asset sync before
building a package:

```bash
make frontend-build
make runtime-assets-sync
make package-check
```

## Docker Compose Compatibility

The old OS launchers still start the deprecated Compose/PostgreSQL topology for
one transition release. They print a deprecation warning by design.

Check Docker and the compatibility stack with:

```bash
docker info
bash scripts/launch-workbench.sh status
bash scripts/launch-workbench.sh logs
bash scripts/launch-workbench.sh smoke
```

The destructive compatibility reset removes this Compose project's database,
uploads, reports, snapshots, and provider-cache volumes:

```bash
VPW_ASSUME_YES=1 bash scripts/launch-workbench.sh reset
```

Use it only for disposable data. For retained installations, create and verify
a backup first with `scripts/workbench-backup.sh` and follow the
[single-process runtime transition](docs/single-process-runtime-transition.md).
