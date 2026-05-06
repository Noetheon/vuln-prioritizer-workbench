# Vuln Prioritizer Workbench Frontend

This is the React/Vite/TanStack Router workspace for the active Workbench.

The browser app talks to the active FastAPI backend through the generated
`/api/v1` client in `frontend/src/client/**` and the wrapper in
`frontend/src/api-client.ts`.

## Local Commands

```bash
cd frontend && npm ci --workspaces=false
cd frontend && npm run build
bash scripts/generate-client.sh
```

The official template uses Bun. This repository keeps Bun-compatible scripts in
`package.json`, but the audited local and Docker fallback uses npm with the
checked-in `frontend/package-lock.json`.
