# Vuln Prioritizer Workbench Frontend

This is the React workspace for the FastAPI Full Stack Template migration.

The current shell is intentionally thin: it proves the Vite/React workspace,
OpenAPI client generation, and product navigation baseline without claiming
parity with the existing Jinja2 Workbench.

## Local Commands

```bash
npm --prefix frontend install --no-package-lock
npm --prefix frontend run build
bash scripts/generate-client.sh
```

The official template uses Bun. This repository keeps Bun-compatible scripts in
`package.json`, but the local fallback uses npm until Bun is available in the
developer environment.
