# Troubleshooting

This guide covers the local Docker Workbench started by `launch-workbench`.

## Docker Is Not Running

Start Docker Desktop or Docker Engine, wait until Docker reports it is ready,
then rerun:

```bash
bash scripts/launch-workbench.sh start
```

Check Docker manually:

```bash
docker info
docker compose version
```

## Port Already In Use

The launcher automatically falls back from frontend `5173` and backend `8000`
to isolated local ports when it can. To force specific ports:

```bash
DOCKER_DEMO_FRONTEND_PORT=15174 DOCKER_DEMO_BACKEND_PORT=18080 \
  bash scripts/launch-workbench.sh start
```

Windows PowerShell:

```powershell
$env:DOCKER_DEMO_FRONTEND_PORT = "15174"
$env:DOCKER_DEMO_BACKEND_PORT = "18080"
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 start
```

## Containers Start But The App Does Not Open

Check service state and logs:

```bash
bash scripts/launch-workbench.sh status
bash scripts/launch-workbench.sh logs
```

Run the API smoke test when the backend is reachable:

```bash
bash scripts/launch-workbench.sh smoke
```

## Database Or Migration Errors

First try a normal restart:

```bash
bash scripts/launch-workbench.sh stop
bash scripts/launch-workbench.sh start
```

If the local data is disposable, reset this Workbench project:

```bash
bash scripts/launch-workbench.sh reset
```

`reset` deletes only the Docker Compose resources for the configured
`COMPOSE_PROJECT_NAME`. It removes the local database, import upload volume,
report volume, provider snapshot volume, and provider cache volume for this
Workbench instance.

## Windows Execution Policy

Use the checked-in BAT launcher or run PowerShell with a process-local bypass:

```powershell
launch-workbench.bat
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 start
```

This does not change the machine-wide PowerShell execution policy.

## macOS Permission Or Quarantine Issues

After extracting a downloaded ZIP, macOS may require executable permissions:

```bash
chmod +x launch-workbench.command scripts/launch-workbench.sh
./launch-workbench.command
```

If Gatekeeper quarantine blocks the launcher from a downloaded archive:

```bash
xattr -dr com.apple.quarantine .
./launch-workbench.command
```

Only run this inside the extracted Workbench folder after verifying the release
source.

## Update Problems

The `update` command uses `git pull --ff-only` only when the worktree is clean.
If local changes exist, it prints `git status --short`, skips the pull, rebuilds
from the current checkout, and starts the Workbench.

```bash
bash scripts/launch-workbench.sh update
```

For release ZIP installs, download a newer release ZIP and extract it to a new
folder.

## Diagnostics Bundle

Create a local redacted support bundle:

```bash
bash scripts/launch-workbench.sh diagnostics
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 diagnostics
```

The bundle is written under `diagnostics/` and includes Compose status, recent
service logs, backend Workbench status, provider status, demo status, Docker
versions, and Git status when available.

The bundle intentionally excludes `.env` files, database dumps, uploaded import
files, generated reports, and provider cache contents. Review the files before
sharing them.

## Full Local Rebuild

When Docker image state looks stale but data should stay:

```bash
bash scripts/launch-workbench.sh stop
docker compose -f compose.yml -f compose.override.yml build --no-cache backend frontend worker
bash scripts/launch-workbench.sh start
```

When local data can be discarded:

```bash
VPW_ASSUME_YES=1 bash scripts/launch-workbench.sh reset
bash scripts/launch-workbench.sh start
```
