# Workbench Public Deployment Runbook

This runbook covers the additional controls required before exposing the
Workbench beyond a local or private single-workspace environment.

Status: deployment-control runbook, not final certification. Public-production
readiness remains gated by the PP5 scorecard and the
[Public-Production Release Evidence Ledger](./public-production-release-evidence-ledger.md).

## Required Environment

Use non-default secrets and exact public origins:

```bash
ENVIRONMENT=production
SECRET_KEY=<long random value>
FIRST_SUPERUSER_PASSWORD=<long random value>
DOMAIN=workbench.example.com
FRONTEND_HOST=https://workbench.example.com
VITE_API_URL=
BACKEND_CORS_ORIGINS=https://workbench.example.com
ALLOWED_HOSTS=workbench.example.com,api.workbench.example.com
API_DOCS_ENABLED=false
TRAEFIK_APP_ENABLED=true
TRAEFIK_DASHBOARD_ENABLED=false
```

Production and staging reject wildcard CORS, localhost CORS, non-HTTPS CORS, and
origin values that include paths. Keep `ALLOWED_HOSTS` exact and do not include
ports or schemes.

The public browser default is same-origin API routing: leave `VITE_API_URL`
empty so the built frontend calls `/api/v1/...` through the frontend reverse
proxy. A split API domain such as `https://api.workbench.example.com` is a
separate deployment variant and must update CSP `connect-src`, CORS,
`ALLOWED_HOSTS`, cookie domain/path, and CSRF verification together before it is
approved for public browser traffic.

## Reverse Proxy And TLS

`compose.traefik.yml` provides the public reverse proxy. App routing is opt-in
with `TRAEFIK_APP_ENABLED=true`.

- Frontend route: `https://${DOMAIN}`.
- Browser API route: same-origin `https://${DOMAIN}/api/...`.
- Optional direct API route for automation: `https://api.${DOMAIN}` only when
  its CSP/CORS/cookie/CSRF contract is reviewed as a split-domain deployment.
- HTTP is redirected to HTTPS.
- Traefik terminates TLS through the configured ACME resolver.
- Backend upload requests are bounded by
  `TRAEFIK_MAX_REQUEST_BODY_BYTES`, which should match or stay slightly above
  `MAX_UPLOAD_MB`.
- Keep the Traefik dashboard disabled. If enabled for maintenance, set a narrow
  `TRAEFIK_DASHBOARD_IP_ALLOWLIST`.

Do not trust arbitrary forwarded headers from the public internet. Place Traefik
as the only public entrypoint and keep backend container ports unbound except in
local override files.

## Rate Limits And Sessions

The backend enables per-process rate limiting by default:

```bash
RATE_LIMIT_ENABLED=true
API_RATE_LIMIT_PER_MINUTE=600
LOGIN_RATE_LIMIT_PER_MINUTE=60
TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE=60
```

Browser JWTs include a persisted session ID. `/api/v1/login/logout` revokes the
current session, and revoked or expired sessions are rejected before a user is
returned to API routes.

For horizontally scaled deployments, replace the in-process limiter with a
shared store before increasing replica count.

## Audit And Retention

The `audit_event` table records login lifecycle, project lifecycle, token
lifecycle, imports, report create/download/verify, waivers, assets, provider
jobs, GitHub issue exports, and retention cleanup. API token secrets and token
hashes are never returned by audit routes.

Retention windows are configured through:

```bash
AUDIT_RETENTION_DAYS=365
SESSION_RETENTION_DAYS=30
REVOKED_API_TOKEN_RETENTION_DAYS=365
```

Preview cleanup:

```bash
python -m app.core.retention --dry-run
```

Apply cleanup:

```bash
python -m app.core.retention
```

Project deletion removes managed upload/report artifact trees for the project
and writes an audit event with the removed and missing managed paths.

## Backup

Back up both the database and managed artifact roots before upgrades and before
running retention cleanup.

SQLite:

```bash
SQLITE_DATABASE_PATH=template.db \
WORKBENCH_ARTIFACT_PATHS="data/template-import-uploads data/template-reports data/template-provider-cache data/provider-snapshots" \
scripts/workbench-backup.sh
```

Postgres:

```bash
POSTGRES_SERVER=localhost POSTGRES_PORT=5432 POSTGRES_DB=workbench POSTGRES_USER=workbench \
PGPASSWORD=<password> \
scripts/workbench-backup.sh
```

Docker Compose named volumes:

```bash
WORKBENCH_DATABASE_MODE=compose \
WORKBENCH_ARTIFACT_MODE=compose \
scripts/workbench-backup.sh
```

`WORKBENCH_DATABASE_MODE=compose` runs `pg_dump` inside the Compose `db`
container, so the default stack does not need to publish Postgres on the host.
`WORKBENCH_ARTIFACT_MODE=compose` copies artifacts from the running backend
container, including the import-upload, report, provider-snapshot, and
provider-cache Compose volumes.

Some historical artifact directory names are retained as storage-path
compatibility names for the active `backend/app` runtime. They do not indicate a
separate template-era Workbench runtime, and API responses expose managed
artifact IDs or relative references rather than container filesystem paths.

The script writes a timestamped directory under `./backups` unless `BACKUP_DIR`
is set. Artifact paths are packed into `artifacts.tar`.

## Restore

Restore into an empty or intentionally replaced environment.

SQLite:

```bash
SQLITE_DATABASE_PATH=template.db scripts/workbench-restore.sh backups/<backup-dir>
alembic -c backend/alembic.ini upgrade head
```

Docker Compose named volumes:

```bash
WORKBENCH_DATABASE_MODE=compose \
WORKBENCH_ARTIFACT_MODE=compose \
scripts/workbench-restore.sh backups/<backup-dir>
docker compose exec backend alembic -c /app/backend/alembic.ini upgrade head
```

Postgres:

```bash
POSTGRES_SERVER=localhost POSTGRES_PORT=5432 POSTGRES_DB=workbench POSTGRES_USER=workbench \
PGPASSWORD=<password> \
scripts/workbench-restore.sh backups/<backup-dir>
alembic -c backend/alembic.ini upgrade head
```

After restore, verify:

```bash
python -m app.core.migration_bootstrap
alembic -c backend/alembic.ini upgrade head
python -c "import urllib.request; print(urllib.request.urlopen('https://${DOMAIN}/api/v1/workbench/health', timeout=5).read().decode())"
```

The public health response should only report a minimal OK status. Verify
`/api/v1/workbench/status` with an authenticated admin session or automation API
token before promoting the restored environment; that auth-gated status response
should report `database_status=ready` and `schema_status=ready`.

## Release Evidence

Before a public-production release claim, record these public-safe results in
the release evidence ledger or linked issue evidence:

- `make release-readiness-check`
- `make package-check`
- `make dependency-audit`
- `make api-client-drift-check`
- `make docker-demo-smoke`
- `make docker-production-smoke`
- `make playwright-check`
- header captures for the public frontend and API routes
- residual-risk decision with owner and follow-up issue for every exception

Do not include secrets, token values, cookies, customer exports, private
absolute paths, shell history, or unredacted environment dumps in public
evidence.
