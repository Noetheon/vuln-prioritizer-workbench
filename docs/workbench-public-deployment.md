# Local And Private Workbench Deployment Runbook

This runbook covers local and private single-operator Workbench deployments.
The active product target is a self-hosted Workbench for a trusted operator, not
a shared SaaS or internet-facing multi-user service.

Status: local/private deployment guidance. Public or shared exposure is outside
the normal product scope and remains a future reviewed security decision. The
historical VPW-AUD-999 final scorecard closed on 2026-05-08; any public or
shared deployment still needs fresh evidence in the
[Public-Production Release Evidence Ledger](./public-production-release-evidence-ledger.md)
for the exact candidate and topology.

## Required Environment

Use non-default secrets and exact public origins:

```bash
ENVIRONMENT=production
SECRET_KEY=<random value with at least 32 characters>
POSTGRES_PASSWORD=<long random value>
DOMAIN=workbench.example.com
FRONTEND_HOST=https://workbench.example.com
VITE_API_URL=
BACKEND_CORS_ORIGINS=https://workbench.example.com
ALLOWED_HOSTS=workbench.example.com,api.workbench.example.com
API_DOCS_ENABLED=false
DECISION_API_MAX_FINDINGS=1000
TRAEFIK_APP_ENABLED=true
TRAEFIK_APP_IP_ALLOWLIST=<operator-or-private-network-cidr>
TRAEFIK_API_IP_ALLOWLIST=<automation-source-cidr>
TRAEFIK_DASHBOARD_ENABLED=false
```

Production and staging reject wildcard CORS, localhost CORS, non-HTTPS CORS, and
origin values that include paths. Keep `ALLOWED_HOSTS` exact and do not include
ports or schemes.

Production and staging also reject known placeholder secrets and `SECRET_KEY`
values shorter than 32 characters. The standalone backend container requires
`SECRET_KEY` to be set before it starts; Compose requires that value plus
`POSTGRES_PASSWORD`.

The public browser default is same-origin API routing: leave `VITE_API_URL`
empty so the built frontend calls `/api/v1/...` through the frontend reverse
proxy. A split API domain such as `https://api.workbench.example.com` is a
separate deployment variant and must update CSP `connect-src`, CORS, and
`ALLOWED_HOSTS` together before it is approved for public browser traffic. If a
future deployment reintroduces browser-session auth, its cookie and CSRF design
must be reviewed in the same change.

## Reverse Proxy And TLS

`compose.traefik.yml` provides the public reverse proxy. App routing is opt-in
with `TRAEFIK_APP_ENABLED=true`, and the HTTPS app router is always guarded by
the `workbench-app-ipallowlist` Traefik middleware. The default source range is
`127.0.0.1/32`, so enabling the route without an operator-supplied
`TRAEFIK_APP_IP_ALLOWLIST` stays fail-closed for remote clients.

- Frontend route: `https://${DOMAIN}`.
- Browser API route: same-origin `https://${DOMAIN}/api/...`.
- Optional direct API route for automation: `https://api.${DOMAIN}` only when
  its CSP/CORS contract is reviewed as a split-domain deployment and
  `TRAEFIK_API_IP_ALLOWLIST` is set to the exact automation source range.
- HTTP is redirected to HTTPS.
- Traefik terminates TLS through the configured ACME resolver.
- The Workbench app and optional direct API routers must keep Traefik
  `ipallowlist` middleware in front of every HTTPS route because the active
  Workbench does not implement browser login, RBAC, or API-token enforcement.
- The Traefik container uses a read-only root filesystem, `no-new-privileges`,
  dropped Linux capabilities with only `NET_BIND_SERVICE` restored, a writable
  `/tmp` tmpfs, and a dedicated ACME certificate volume.
- Backend upload requests are bounded by
  `TRAEFIK_MAX_REQUEST_BODY_BYTES`, which should match or stay slightly above
  `MAX_UPLOAD_MB`.
- Generated reports are bounded by `MAX_REPORT_MB` per artifact and
  `MAX_REPORTS_PER_RUN` retained artifacts per analysis run.
- Keep the Traefik dashboard disabled. If enabled for maintenance, set a narrow
  `TRAEFIK_DASHBOARD_IP_ALLOWLIST` and a htpasswd-compatible
  `TRAEFIK_DASHBOARD_AUTH_USERS` value. Without an operator-supplied auth hash,
  the Compose default is a non-operational placeholder user.

Do not trust arbitrary forwarded headers from the public internet. Place Traefik
as the only public entrypoint and keep backend container ports unbound except in
local override files.

## Public TLS Evidence Checklist

This checklist is not part of the normal single-user local/private path. Use it
only if a future reviewed decision intentionally exposes the Workbench beyond a
trusted local host. For the current product scope, acceptable exposure is a
private network or an operator edge protected by the Traefik app/API IP
allowlists documented above. Do not use this checklist to certify unauthenticated
internet-wide Workbench access.

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
  approved. Capture this only from an allowed operator source address.
- `https://${DOMAIN}/api/v1/workbench/health` returns the minimal public health
  response for allowed operator sources.
- `https://${DOMAIN}/api/v1/workbench/status` returns local Workbench readiness
  without requiring a browser login only after the edge allowlist permits the
  operator source.
- `https://${DOMAIN}/api/v1/providers/status` returns redacted provider
  diagnostics for the local Workbench status UI only after the edge allowlist
  permits the operator source.
- `https://${DOMAIN}/docs` and `/api/v1/openapi.json` are not public when
  `API_DOCS_ENABLED=false`.
- `https://api.${DOMAIN}/api/v1/workbench/health` is treated as the Optional
  direct API route for automation; if exposed publicly, record the split-domain
  CORS, CSP, host-routing, and `TRAEFIK_API_IP_ALLOWLIST` decision in the release
  evidence ledger.
- HTTP requests redirect to HTTPS.
- Requests from outside `TRAEFIK_APP_IP_ALLOWLIST` and
  `TRAEFIK_API_IP_ALLOWLIST` are denied by Traefik before reaching the
  Workbench services.
- Traefik dashboard routing stays disabled unless a short maintenance window,
  IP allowlist, and dashboard Basic Auth users are documented.

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

For a local reset, back up the current Workbench volumes with
`WORKBENCH_ARTIFACT_MODE=compose`, start a fresh stack with Workbench-branded
volume names, then restore the backup into the new stack.

## Rate Limits And Local Automation Tokens

The backend enables per-process rate limiting by default:

```bash
RATE_LIMIT_ENABLED=true
API_RATE_LIMIT_PER_MINUTE=600
TRUSTED_PROXY_CIDRS=
```

Set `TRUSTED_PROXY_CIDRS` only to the network ranges of reverse proxies that
are the sole public entrypoint. When configured, rate-limit buckets use the
first `X-Forwarded-For` address only for requests received from those trusted
proxy CIDRs. Leave it blank when the backend is reachable directly.

The active browser Workbench is local single-user and does not require a login
step. The active API no longer exposes login, user-management, API-token, or
session-list routes. Bearer headers are ignored by the local principal path
rather than enabling scoped token enforcement. Because of that product boundary,
private or edge-allowlisted deployments must keep the Traefik app/API
allowlists active; do not replace them with CORS, Host validation, or API docs
disablement, because none of those controls authenticate an operator.

The current migration head drops the inactive API-token and auth-session
tables. Treat any future reintroduction of
automation tokens, browser login, or shared-user access as a new reviewed
security design.

For horizontally scaled deployments, replace the in-process limiter with a
shared store before increasing replica count; the built-in limiter is still
per-process even when trusted proxy parsing is enabled. The in-process limiter
also bounds stored rate-limit keys to prevent unbounded memory growth, which is
a local-process safety guard rather than a distributed public-deployment quota.

## Audit And Retention

The `audit_event` table records project lifecycle, imports, report
create/download/verify, waivers, assets, provider jobs, GitHub issue exports,
and retention cleanup. Historical rows may still contain legacy login or token
lifecycle actions from older local runs.

Retention windows are configured through:

```bash
AUDIT_RETENTION_DAYS=365
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

The backup script uses Workbench-branded artifact roots by default. API
responses expose managed artifact IDs or relative references rather than
container filesystem paths.

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
alembic -c backend/alembic.ini upgrade head
python -c "import urllib.request; print(urllib.request.urlopen('https://${DOMAIN}/api/v1/workbench/health', timeout=5).read().decode())"
```

The public health response should only report a minimal OK status. Verify
`/api/v1/workbench/status` before promoting the restored environment; that local
readiness response should report `database_status=ready` and
`schema_status=ready`.

## Release Evidence

Before a public or shared deployment claim, record these public-safe results in
the release evidence ledger or linked issue evidence. The normal
`make release-readiness-check` gate is local/self-hosted readiness; it does not
include the explicit public-deployment evidence contract.

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
