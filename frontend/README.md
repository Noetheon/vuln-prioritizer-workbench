# Vuln Prioritizer Workbench Frontend

This is the React/Vite/TanStack Router workspace for the active Workbench.

The browser app talks to the active FastAPI backend through the generated
`/api/v1` client in `frontend/src/client/**`.

Production browser builds should keep `VITE_API_URL` empty so requests use the
same-origin `/api/...` nginx proxy. Split API domains must update CSP, CORS,
cookie, and CSRF settings as one deployment decision.

`frontend/src/api-client.ts` is a manual wrapper over the generated client. It is
owned like normal frontend source and should not be treated as generated drift.

## Local Commands

```bash
cd frontend && npm ci --workspaces=false
cd frontend && npm run build
cd frontend && npm run test -- tests/accessibility.spec.ts
bash scripts/generate-client.sh
git diff --exit-code -- frontend/src/client
```

The official template uses Bun. This repository keeps Bun-compatible scripts in
`package.json`, but the audited local and Docker fallback uses npm with the
checked-in `frontend/package-lock.json`.
