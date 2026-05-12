# VPW-028 Provider Status API Card

VPW-028 defines the Workbench provider status read contract used by the React
Workbench status card. It does not replace provider enrichment, snapshot replay,
or update jobs.

## Route

The active backend exposes:

```http
GET /api/v1/providers/status
```

The active local Workbench uses same-origin browser access for this route.
Optional `vpr_` service tokens may be supplied by automation; when present, the
backend enforces their scopes and expiry.

## Response Contract

The response is a UI-oriented status envelope over the latest Workbench
`provider_snapshot` record, provider cache settings, and latest provider update
job.

Top-level fields:

- `status`: `ok` when the latest provider evidence is usable, otherwise
  `degraded`.
- `snapshot`: latest persisted provider snapshot summary, including id, content
  hash, generated time, selected sources, requested CVE count, source path,
  locked-provider flag, and missing flag.
- `sources`: one row per provider source, normally `nvd`, `epss`, and `kev`.
- `latest_update_job`: latest provider refresh job, or `null` when no job has
  been recorded.
- `cache_dir`: configured provider cache directory.
- `snapshot_dir`: configured provider snapshot directory.
- `warnings`: redacted warning strings safe for display and evidence bundles.
- `last_sync`: latest successful provider timestamp across source evidence, or
  `null` when unavailable.
- `last_error`: latest provider update error, normally derived from a failed
  update job, or `null`.
- `cache_age_seconds`: age of `last_sync` at response time, or `null` when
  freshness cannot be computed.
- `snapshot_mode`: `locked`, `cache-only`, `snapshot`, or `missing`.

Source rows should include the source name, whether it was selected, whether
usable evidence is available, whether it is stale, its display value, optional
detail text, and source-scoped `last_sync`, `last_error`, and
`cache_age_seconds` when available.

Failed latest update jobs degrade the response and add a warning. They must not
erase the previous usable snapshot identity.

## React Card Evidence

The React provider status card is an evidence surface, not a refresh control.
It should render:

- overall `status` and `snapshot_mode`
- snapshot id or content hash plus generated time when present
- NVD, EPSS, and KEV rows with availability, selected state, and last-sync
  evidence
- `cache_age_seconds` in human-readable form when present
- `last_error` and `warnings` as visible degraded-state evidence
- latest update-job id and status when present

Closure evidence for implementation should include an API contract check,
generated-client usage against `/api/v1/providers/status`, and React test or
screenshot coverage for usable, degraded, and unavailable payloads.
