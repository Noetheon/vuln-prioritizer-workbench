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

Run frontend commands from the repository root so the checked-in wrapper selects
the pinned Node 22 / npm 10 toolchain before applying the same engine-strict
policy as CI and Docker:

```bash
make frontend-check
make playwright-check
scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true run test -- tests/accessibility.spec.ts --project=chromium
make api-client-drift-check
```

The audited local, CI, and Docker fallback paths use npm with the checked-in
`frontend/package-lock.json`. Keep ad hoc npm invocations on the same
`scripts/frontend-npm.sh --prefix frontend --workspaces=false --engine-strict=true`
wrapper unless a Make target already covers the command. Volta and mise are
supported through `.tool-versions` and the frontend package metadata; the
wrapper also recognizes asdf and nvm.

## Dependency Audit Notes

`npx --yes depcheck frontend` is the dependency drift check for this workspace.
The local `.depcheckrc` allowlists the Tailwind CSS entrypoints because they are
resolved through `frontend/src/index.css`, not TypeScript imports. The same
config ignores the local-only `screenshot-polish.mjs` scratch script when it is
present in a developer checkout; it is not tracked or used by CI.

The generated OpenAPI client uses browser-native `FormData`; it does not require
the npm `form-data` package.

Documentation that describes frontend routes, generated-client ownership, or
browser report behavior should be checked against
[`docs/documentation-evidence-matrix.md`](../docs/documentation-evidence-matrix.md)
and the current `frontend/src/**` implementation before historical archive
notes are reused as current product proof.
