# Workbench Public Deployment Runbook

This runbook covers the additional controls required before exposing the
Workbench beyond a local or private single-workspace environment.

Status: deployment-control runbook, not final certification. Public-production
readiness remains gated by the VPW-AUD-999 final scorecard and the
[Public-Production Release Evidence Ledger](./public-production-release-evidence-ledger.md).

## Required Environment

Use non-default secrets and exact public origins:

```bash
ENVIRONMENT=production
SECRET_KEY=<random value with at least 32 characters>
FIRST_SUPERUSER_PASSWORD=<random value with at least 16 characters>
POSTGRES_PASSWORD=<long random value>
DOMAIN=workbench.example.com
FRONTEND_HOST=https://workbench.example.com
VITE_API_URL=
BACKEND_CORS_ORIGINS=https://workbench.example.com
ALLOWED_HOSTS=workbench.example.com,api.workbench.example.com
API_DOCS_ENABLED=false
DECISION_API_MAX_FINDINGS=1000
TRAEFIK_APP_ENABLED=true
TRAEFIK_DASHBOARD_ENABLED=false
```

Production and staging reject wildcard CORS, localhost CORS, non-HTTPS CORS, and
origin values that include paths. Keep `ALLOWED_HOSTS` exact and do not include
ports or schemes.

Production and staging also reject known placeholder secrets, `SECRET_KEY`
values shorter than 32 characters, `FIRST_SUPERUSER_PASSWORD` values shorter
than 16 characters, passwords that equal the configured superuser, and passwords
that equal the secret key. The standalone backend container requires
`SECRET_KEY` and `FIRST_SUPERUSER_PASSWORD` to be set before it starts; Compose
requires those values plus `POSTGRES_PASSWORD`.

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
- Generated reports are bounded by `MAX_REPORT_MB` per artifact and
  `MAX_REPORTS_PER_RUN` retained artifacts per analysis run.
- Keep the Traefik dashboard disabled. If enabled for maintenance, set a narrow
  `TRAEFIK_DASHBOARD_IP_ALLOWLIST`.

Do not trust arbitrary forwarded headers from the public internet. Place Traefik
as the only public entrypoint and keep backend container ports unbound except in
local override files.

## Public TLS Evidence Checklist

Before claiming public-production readiness, capture public-safe evidence from
the exact deployed candidate. Redact cookies, tokens, IP addresses that identify
private infrastructure, private paths, and shell history.

Required topology evidence:

```bash
python3 scripts/check_public_deployment_evidence.py
docker compose -f compose.yml -f compose.traefik.yml config
```

Required public header evidence:

```bash
curl -I https://${DOMAIN}/
curl -I https://${DOMAIN}/api/v1/workbench/health
# Optional split-domain API route, only when TRAEFIK_API_ENABLED=true:
curl -I https://api.${DOMAIN}/api/v1/workbench/health
```

Required browser/API behavior evidence:

- `https://${DOMAIN}/` returns the frontend with security headers and a CSP that
  keeps same-origin API routing unless a split-domain deployment is explicitly
  approved.
- `https://${DOMAIN}/api/v1/workbench/health` returns the minimal public health
  response.
- `https://${DOMAIN}/api/v1/workbench/status` is auth-gated.
- `https://${DOMAIN}/docs` and `/api/v1/openapi.json` are not public when
  `API_DOCS_ENABLED=false`.
- `https://api.${DOMAIN}/api/v1/workbench/health` is treated as the Optional
  direct API route for automation; if exposed publicly, record the split-domain
  CORS, CSRF, cookie, and CSP decision in the release evidence ledger.
- HTTP requests redirect to HTTPS.
- Traefik dashboard routing stays disabled unless a short maintenance window and
  IP allowlist are documented.

Do not include secrets, token values, cookies, customer exports, private
absolute paths, shell history, or unredacted environment dumps in public
evidence.

## Compose Volumes And Compatibility

Fresh Compose stacks use Workbench-branded named volumes by default:

```bash
WORKBENCH_DB_VOLUME=workbench-db-data
WORKBENCH_IMPORT_UPLOADS_VOLUME=workbench-import-uploads
WORKBENCH_REPORTS_VOLUME=workbench-reports
WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME=workbench-provider-snapshots
WORKBENCH_PROVIDER_CACHE_VOLUME=workbench-provider-cache
```

Existing deployments created before the volume rename can temporarily point the
same variables at the historical compatibility names:

```bash
WORKBENCH_IMPORT_UPLOADS_VOLUME=template-import-uploads
WORKBENCH_REPORTS_VOLUME=template-reports
WORKBENCH_PROVIDER_SNAPSHOTS_VOLUME=template-provider-snapshots
WORKBENCH_PROVIDER_CACHE_VOLUME=template-provider-cache
```

Use those compatibility names only to attach, back up, or restore existing
volumes. For a rename migration, back up the old volumes with
`WORKBENCH_ARTIFACT_MODE=compose`, unset the compatibility overrides, start a
fresh stack with Workbench-branded volume names, then restore the backup into
the new stack.

## Rate Limits And Sessions

The backend enables per-process rate limiting by default:

```bash
RATE_LIMIT_ENABLED=true
API_RATE_LIMIT_PER_MINUTE=600
LOGIN_RATE_LIMIT_PER_MINUTE=60
TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE=60
API_TOKEN_DEFAULT_EXPIRE_DAYS=90
TRUSTED_PROXY_CIDRS=
```

Set `TRUSTED_PROXY_CIDRS` only to the network ranges of reverse proxies that
are the sole public entrypoint. When configured, rate-limit buckets use the
first `X-Forwarded-For` address only for requests received from those trusted
proxy CIDRs. Leave it blank when the backend is reachable directly.

Browser JWTs include a persisted session ID. `/api/v1/login/logout` revokes the
current session, and revoked or expired sessions are rejected before a user is
returned to API routes.

Scoped API tokens are created after JWT login and are stored only as hashes.
They support local automation for `read`, `write`, `import`, `report`, or
`admin` API scopes and are rejected when revoked, expired, or tied to an
inactive user. Tokens default to a 90-day expiry unless creation supplies a
future `expires_at` value; API responses expose token metadata including
`expires_at` and computed `active` state. They are not a substitute for the full
public-deployment control set documented in this runbook.

For horizontally scaled deployments, replace the in-process limiter with a
shared store before increasing replica count; the built-in limiter is still
per-process even when trusted proxy parsing is enabled. The in-process limiter
also bounds stored rate-limit keys to prevent unbounded memory growth, which is
a local-process safety guard rather than a distributed public-deployment quota.

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
MAX_REPORT_MB=50
MAX_REPORTS_PER_RUN=20
```

Preview cleanup:

```bash
python -m app.core.retention --dry-run
```

Apply cleanup:

```bash
python -m app.core.retention
```

Report generation rejects artifacts larger than `MAX_REPORT_MB` and prunes the
oldest report artifact directories for the same run after
`MAX_REPORTS_PER_RUN`. Project deletion removes managed upload/report artifact
trees for the project and writes an audit event with the removed and missing
managed paths.

## Backup

Back up both the database and managed artifact roots before upgrades and before
running retention cleanup.

SQLite:

```bash
SQLITE_DATABASE_PATH=workbench.db \
WORKBENCH_ARTIFACT_PATHS="data/workbench-import-uploads data/workbench-reports data/workbench-provider-cache data/provider-snapshots" \
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
POSTGRES_PASSWORD=<password> \
WORKBENCH_DATABASE_MODE=compose \
WORKBENCH_ARTIFACT_MODE=compose \
scripts/workbench-backup.sh
```

`WORKBENCH_DATABASE_MODE=compose` runs `pg_dump` inside the Compose `db`
container, so the default stack does not need to publish Postgres on the host.
`WORKBENCH_ARTIFACT_MODE=compose` copies artifacts from the running backend
container, including the import-upload, report, provider-snapshot, and
provider-cache Compose volumes.

The backup script uses Workbench-branded artifact roots by default. Historical
`data/template-*` artifact directories and template-era Compose volume names are
included only when `WORKBENCH_LEGACY_STORAGE_FALLBACK=1` is set, or when an
explicit `WORKBENCH_ARTIFACT_PATHS` list names them. They are compatibility
paths for existing self-hosted installs, not a separate template-era Workbench
runtime. API responses expose managed artifact IDs or relative references rather
than container filesystem paths.

The script writes a timestamped directory under `./backups` unless `BACKUP_DIR`
is set. Artifact paths are packed into `artifacts.tar`. Restore validates the
tar member list before extraction and refuses absolute paths, `..` traversal,
symlink members, and hardlink members.

## Restore

Restore into an empty or intentionally replaced environment.

SQLite:

```bash
SQLITE_DATABASE_PATH=workbench.db scripts/workbench-restore.sh backups/<backup-dir>
alembic -c backend/alembic.ini upgrade head
```

Docker Compose named volumes:

```bash
POSTGRES_PASSWORD=<password> \
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
- `python3 scripts/check_public_deployment_evidence.py`
- `python3 scripts/check_archive_evidence_manifest.py`
- `make docker-demo-smoke`
- `make docker-production-smoke`
- `make playwright-check`
- Public TLS Evidence Checklist output and header captures for the public
  frontend and API routes
- residual-risk decision with owner and follow-up issue for every exception

Do not include secrets, token values, cookies, customer exports, private
absolute paths, shell history, or unredacted environment dumps in public
evidence.
