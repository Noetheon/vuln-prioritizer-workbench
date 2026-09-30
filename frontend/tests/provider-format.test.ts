import assert from "node:assert/strict"
import test from "node:test"

import type {
  ProviderReachabilityPublic,
  ProviderSourceStatusPublic,
  ProviderStatusPublic,
  WorkbenchStatus,
} from "../src/api-client"
import {
  dataServicesSummary,
  evidenceReadiness,
  formatCacheAge,
  formatProviderFreshness,
  importProviderReadiness,
  providerDataQualityNotes,
  providerDataState,
  providerDataStateLabel,
  providerDataTone,
  providerSnapshotHealth,
  providerSnapshotSummary,
  providerSourceDetail,
  providerSourceLabel,
  providerSourceState,
  providerStaleAfterLabel,
  snapshotModeDescription,
  snapshotModeLabel,
  unreachableProvidersMessage,
  workbenchApiHealth,
  workspaceHealthLabel,
} from "../src/lib/provider-format.ts"

function providerStatus(
  overrides: Partial<ProviderStatusPublic> = {},
  snapshot: Partial<ProviderStatusPublic["snapshot"]> = {},
): ProviderStatusPublic {
  return {
    cache_age_seconds: 7200,
    import_provider_mode: "live",
    last_error: null,
    last_sync: "2026-05-01T10:00:00Z",
    snapshot: { missing: false, mode: "snapshot", ...snapshot },
    snapshot_mode: "snapshot",
    sources: [],
    stale_after_hours: 72,
    status: "ok",
    warnings: [],
    ...overrides,
  } as ProviderStatusPublic
}

function source(
  overrides: Partial<ProviderSourceStatusPublic>,
): ProviderSourceStatusPublic {
  return {
    available: true,
    name: "nvd",
    selected: true,
    stale: false,
    ...overrides,
  } as ProviderSourceStatusPublic
}

test("provider data state follows the backend status, errors first", () => {
  assert.equal(providerDataState(null), "checking")
  assert.equal(providerDataState(providerStatus()), "fresh")
  assert.equal(providerDataState(providerStatus({ status: "stale" })), "stale")
  assert.equal(
    providerDataState(providerStatus({ status: "not_loaded" })),
    "not_loaded",
  )
  assert.equal(
    providerDataState(providerStatus({ status: "degraded" })),
    "degraded",
  )
  assert.equal(
    providerDataState(providerStatus({ last_error: "boom" })),
    "degraded",
  )
  assert.equal(
    providerDataState(providerStatus({ status: "unexpected" })),
    "degraded",
  )
  assert.equal(providerDataStateLabel(providerStatus({ status: "stale" })), "Stale")
  assert.equal(
    providerDataStateLabel(providerStatus({ status: "not_loaded" })),
    "Not fetched yet",
  )
  assert.equal(providerDataTone(providerStatus()), "success")
  assert.equal(providerDataTone(providerStatus({ status: "stale" })), "warning")
  assert.equal(
    providerDataTone(providerStatus({ status: "not_loaded" })),
    "info",
  )
})

test("old data is never reported as fresh", () => {
  const stale = formatProviderFreshness(
    providerStatus({ cache_age_seconds: 160 * 86400, status: "stale" }),
  )
  assert.equal(stale.value, "Stale")
  assert.equal(stale.detail, "160d old; stale after 72 hours")
  assert.equal(stale.tone, "high")

  const staleWithoutAge = formatProviderFreshness(
    providerStatus({
      cache_age_seconds: null,
      status: "stale",
      warnings: ["Provider data is older than 72 hours or missing for: KEV."],
    }),
  )
  assert.equal(
    staleWithoutAge.detail,
    "Provider data is older than 72 hours or missing for: KEV.",
  )

  assert.deepEqual(formatProviderFreshness(providerStatus()), {
    detail: "2h old",
    tone: "kev",
    value: "Fresh",
  })
  assert.equal(formatProviderFreshness(null).value, "Loading")
  assert.equal(
    formatProviderFreshness(providerStatus({ status: "not_loaded" })).value,
    "Not fetched yet",
  )
  assert.deepEqual(
    formatProviderFreshness(providerStatus({ last_error: "NVD timed out" })),
    { detail: "NVD timed out", tone: "high", value: "Needs attention" },
  )
})

test("stale threshold comes from the backend", () => {
  assert.equal(providerStaleAfterLabel(providerStatus()), "Stale after 72 hours")
  assert.equal(
    providerStaleAfterLabel(providerStatus({ stale_after_hours: 1 })),
    "Stale after 1 hour",
  )
  assert.equal(
    providerStaleAfterLabel(providerStatus({ stale_after_hours: null })),
    "Stale threshold not reported",
  )
})

test("import readiness names the provider data an import will use", () => {
  assert.deepEqual(importProviderReadiness(providerStatus(), "snapshot.json"), {
    label: "snapshot.json",
    message: "The selected provider snapshot is replayed for this import.",
    status: "passed",
  })
  assert.equal(importProviderReadiness(null).status, "warning")
  assert.deepEqual(importProviderReadiness(providerStatus({ status: "not_loaded" })), {
    label: "Live provider data",
    message: "NVD, EPSS, and KEV are fetched live during the import and cached.",
    status: "passed",
  })
  assert.equal(
    importProviderReadiness(providerStatus({ last_error: "NVD timed out" }))
      .status,
    "warning",
  )

  const defaultSnapshot = { import_provider_mode: "default_snapshot" }
  assert.equal(
    importProviderReadiness(providerStatus(defaultSnapshot)).status,
    "passed",
  )
  assert.equal(
    importProviderReadiness(providerStatus(defaultSnapshot, { missing: true }))
      .status,
    "warning",
  )
  const staleDefault = importProviderReadiness(
    providerStatus({
      ...defaultSnapshot,
      status: "stale",
      warnings: ["Provider data is older than 72 hours."],
    }),
  )
  assert.equal(staleDefault.status, "warning")
  assert.match(staleDefault.message, /older than 72 hours/)
})

function reachability(
  unreachable: Record<string, string | null> = {},
): ProviderReachabilityPublic {
  return {
    checked_at: "2026-05-01T10:00:00Z",
    sources: [
      ["nvd", "NVD"],
      ["epss", "EPSS"],
      ["kev", "KEV"],
    ].map(([source, label]) => ({
      detail: unreachable[source] ?? null,
      label,
      reachable: !(source in unreachable),
      source,
    })),
  }
}

test("a live import warns when a feed does not answer", () => {
  assert.deepEqual(
    importProviderReadiness(providerStatus(), null, reachability()),
    importProviderReadiness(providerStatus()),
  )
  assert.deepEqual(
    importProviderReadiness(
      providerStatus({ last_error: "NVD timed out" }),
      null,
      reachability({ epss: "HTTP 403" }),
    ),
    {
      label: "Live provider data",
      message:
        "EPSS (HTTP 403) does not answer from this Workbench. The import still runs, but priorities will be computed without EPSS. To import without live data, enter a provider snapshot under Add context.",
      status: "warning",
    },
  )
  // A picked snapshot or the runtime's default snapshot needs no live feed.
  assert.equal(
    importProviderReadiness(
      providerStatus(),
      "snapshot.json",
      reachability({ nvd: "Timed out" }),
    ).status,
    "passed",
  )
  assert.equal(
    importProviderReadiness(
      providerStatus({ import_provider_mode: "default_snapshot" }),
      null,
      reachability({ nvd: "Timed out" }),
    ).status,
    "passed",
  )
})

test("unreachable feeds name what the import loses", () => {
  assert.equal(
    unreachableProvidersMessage(
      reachability({ epss: null, kev: "Connection failed", nvd: "Timed out" })
        .sources,
    ),
    "NVD (Timed out), EPSS, and KEV (Connection failed) do not answer from this Workbench. The import still runs, but CVSS scores and descriptions will be missing, priorities will be computed without EPSS, and KEV status will come from the cached catalog, or stay unknown without one. To import without live data, enter a provider snapshot under Add context.",
  )
  assert.match(
    unreachableProvidersMessage(
      reachability({ epss: null, nvd: null }).sources.filter(
        (source) => !source.reachable,
      ),
    ),
    /^NVD and EPSS do not answer .* but CVSS scores and descriptions will be missing and priorities will be computed without EPSS\./,
  )
  assert.match(
    unreachableProvidersMessage([
      { label: "OSV", reachable: false, source: "osv" },
    ]),
    /^OSV does not answer .* but OSV data will be missing\./,
  )
})

test("snapshot mode labels say where the data comes from", () => {
  assert.equal(snapshotModeLabel(null), "Checking")
  assert.equal(
    snapshotModeLabel(providerStatus({ snapshot_mode: "live" }, { missing: true })),
    "Live provider data",
  )
  assert.equal(
    snapshotModeLabel(providerStatus({}, { locked_provider_data: true })),
    "Locked snapshot",
  )
  assert.equal(
    snapshotModeLabel(providerStatus({ snapshot_mode: "demo" }, { mode: "demo" })),
    "Demo snapshot",
  )
  assert.equal(
    snapshotModeLabel(providerStatus({}, { mode: "replay" })),
    "Replay snapshot",
  )
  assert.equal(
    snapshotModeLabel(providerStatus({}, { mode: "missing" })),
    "No snapshot",
  )
  assert.equal(
    snapshotModeLabel(providerStatus({}, { mode: "cache-only" })),
    "Stored snapshot",
  )
  assert.match(
    snapshotModeDescription(providerStatus({ snapshot_mode: "live" })),
    /fetch NVD, EPSS, and KEV live/,
  )
  assert.match(
    snapshotModeDescription(providerStatus({}, { mode: "demo" })),
    /as old as the snapshot/,
  )
  assert.match(
    snapshotModeDescription(providerStatus({}, { locked_provider_data: true })),
    /deterministic/,
  )
  assert.match(
    snapshotModeDescription(providerStatus({}, { mode: "replay" })),
    /replay/,
  )
  assert.match(
    snapshotModeDescription(providerStatus()),
    /latest stored provider snapshot/,
  )
  assert.equal(snapshotModeDescription(null), "Snapshot status is still loading.")
})

test("summaries and notes use the same states", () => {
  assert.equal(providerSnapshotHealth(providerStatus({ status: "stale" })), "Stale")
  assert.equal(providerSnapshotSummary(null), "Provider data loading")
  assert.equal(providerSnapshotSummary(providerStatus()), "Provider data is fresh")
  assert.equal(
    providerSnapshotSummary(providerStatus({ status: "stale" })),
    "Provider data is stale",
  )
  assert.equal(
    providerSnapshotSummary(providerStatus({ status: "not_loaded" })),
    "Provider data not fetched yet",
  )
  assert.equal(
    providerSnapshotSummary(providerStatus({ status: "degraded" })),
    "Provider data needs attention",
  )

  assert.match(
    providerDataQualityNotes(providerStatus({ snapshot_mode: "live" }))[0],
    /last fetched/,
  )
  const snapshotNotes = providerDataQualityNotes(
    providerStatus({}, { locked_provider_data: true }),
  )
  assert.match(snapshotNotes[0], /not when the snapshot was stored/)
  assert.match(snapshotNotes[1], /^Stale after 72 hours\./)
  assert.match(snapshotNotes[2], /Locked replay/)
})

test("source and workspace helpers", () => {
  assert.equal(formatCacheAge(null), "No cache age")
  assert.equal(formatCacheAge(42), "42s")
  assert.equal(formatCacheAge(600), "10m")
  assert.equal(providerSourceLabel(source({ name: "epss" })), "EPSS")
  assert.equal(providerSourceState(source({ stale: true })), "stale")
  assert.equal(providerSourceState(source({ available: false })), "missing")
  assert.equal(providerSourceState(source({})), "available")
  assert.equal(
    providerSourceDetail(source({ last_error: "rate limited" })),
    "rate limited",
  )
  assert.equal(
    providerSourceDetail(source({ detail: null })),
    "No provider detail recorded.",
  )

  const ready = { status: "ready" } as WorkbenchStatus
  assert.equal(workspaceHealthLabel(ready, ""), "Data services healthy")
  assert.equal(workspaceHealthLabel(null, "offline"), "offline")
  assert.equal(workspaceHealthLabel(null, ""), "Data services unavailable")
  assert.equal(workbenchApiHealth(null), "Checking")
  assert.equal(workbenchApiHealth({ status: "degraded" } as WorkbenchStatus), "Unavailable")
  assert.equal(evidenceReadiness(null), "Checking")
  assert.equal(evidenceReadiness(providerStatus({ last_error: "x" })), "Needs attention")
  assert.equal(evidenceReadiness(providerStatus()), "Evidence ready")
  assert.deepEqual(dataServicesSummary(ready, providerStatus({ status: "stale" })), [
    { label: "Data services", value: "Healthy" },
    { label: "Workbench API", value: "Ready" },
    { label: "Provider data", value: "Stale" },
    { label: "Evidence", value: "Evidence ready" },
  ])
})
