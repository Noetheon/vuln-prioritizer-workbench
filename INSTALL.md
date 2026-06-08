# Install And Launch

This guide is for people who want to run Vuln Prioritizer Workbench locally
after cloning the repository or downloading a GitHub Release ZIP.

![Workbench dashboard](docs/examples/media/workbench-dashboard.png)

## Requirements

- Docker Desktop on macOS or Windows, or Docker Engine with the Compose plugin
  on Linux.
- Git when installing from a repository clone.
- Python 3 when running the optional smoke test.

The Workbench is a local, single-user application. The launcher starts
PostgreSQL, the FastAPI backend, the workflow worker, and the React frontend
through Docker Compose.

## Install From Git

```bash
git clone https://github.com/Noetheon/vuln-prioritizer-workbench.git
cd vuln-prioritizer-workbench
bash scripts/launch-workbench.sh start
```

The launcher creates a local `.env` from `.env.example` when needed, generates
local-only secrets, enables the demo workspace for the Docker quickstart, builds
images, waits for readiness, and prints the frontend URL.

## Install From A GitHub Release ZIP

1. Download `vuln-prioritizer-workbench-local-X.Y.Z.zip` from the GitHub
   Release assets.
2. Extract the ZIP.
3. Open a terminal in the extracted folder.
4. Start the Workbench with the launcher for your OS.

The release ZIP contains the same local Docker Workbench sources and launchers
as a repository checkout, plus `BUNDLE-MANIFEST.json` with file SHA-256 values.

## macOS

Double-click `launch-workbench.command`, or run:

```bash
./launch-workbench.command
```

If macOS blocks execution after downloading a ZIP, run:

```bash
chmod +x launch-workbench.command scripts/launch-workbench.sh
./launch-workbench.command
```

## Linux

```bash
bash scripts/launch-workbench.sh start
```

## Windows

Double-click `launch-workbench.bat`, or run PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 start
```

## Launcher Commands

macOS/Linux:

```bash
bash scripts/launch-workbench.sh start
bash scripts/launch-workbench.sh status
bash scripts/launch-workbench.sh logs
bash scripts/launch-workbench.sh smoke
bash scripts/launch-workbench.sh update
bash scripts/launch-workbench.sh diagnostics
bash scripts/launch-workbench.sh stop
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 start
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 status
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 logs
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 smoke
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 update
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 diagnostics
powershell -ExecutionPolicy Bypass -File scripts\launch-workbench.ps1 stop
```

`reset` deletes this Workbench project's Docker volumes, including the local
database, uploaded imports, generated reports, and provider cache:

```bash
bash scripts/launch-workbench.sh reset
```

For non-interactive reset automation, set `VPW_ASSUME_YES=1`.

## Ports

The launcher prefers frontend `http://127.0.0.1:5173` and backend
`http://127.0.0.1:8000`. If those ports are busy, it falls back to isolated
local ports and prints the actual URLs.

Manual Docker Compose startup remains supported:

```bash
cp .env.example .env
docker compose -f compose.yml -f compose.override.yml up --build backend frontend worker
```

## First Run Demo

Open the printed frontend URL and use the dashboard action to load the demo
workspace. The local Docker launcher enables the demo workspace by default.

To refresh reproducible demo screenshot evidence for maintainers:

```bash
make demo-screenshot
```

## Troubleshooting

Use `TROUBLESHOOTING.md` for Docker, port, permission, reset, and diagnostics
issues. The safest support bundle command is:

```bash
bash scripts/launch-workbench.sh diagnostics
```
