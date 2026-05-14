import { expect, test } from "@playwright/test"

import type { ProviderStatusPublic } from "../src/api-client"
import { mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

const degradedProviderStatus: ProviderStatusPublic = {
  cache_age_seconds: 172_800,
  cache_dir: "/var/tmp/vpw/cache",
  last_error: "EPSS refresh failed",
  last_sync: "2025-04-30T10:00:00Z",
  latest_update_job: {
    error_message: "EPSS refresh failed",
    execution_mode: "background",
    finished_at: "2025-04-30T10:05:00Z",
    id: "provider-job-1",
    metadata: {
      cache_only: true,
      reason: "scheduled refresh",
    },
    requested_sources: ["nvd", "epss", "kev"],
    started_at: "2025-04-30T10:00:00Z",
    status: "failed",
  },
  snapshot: {
    content_hash: "sha256:vpw-provider-snapshot",
    generated_at: "2025-04-30T10:04:00Z",
    id: "snapshot-2025-04-30",
    locked_provider_data: false,
    missing: false,
    mode: "cache-only",
    nvd_last_sync: "2025-04-30T09:55:00Z",
    requested_cves: 42,
    selected_sources: ["nvd", "epss", "kev"],
    source_hashes: {
      epss: "epss-cache-hash",
      kev: "kev-cache-hash",
      nvd: "nvd-cache-hash",
    },
    source_metadata: {
      snapshot_id: "snapshot-2025-04-30",
    },
    source_path: "/var/tmp/vpw/snapshots/provider.json",
  },
  snapshot_dir: "/var/tmp/vpw/snapshots",
  snapshot_mode: "cache-only",
  sources: [
    {
      available: true,
      cache_age_seconds: 300,
      detail: "NVD CVE metadata cache is available.",
      last_sync: "2025-04-30T09:55:00Z",
      name: "nvd",
      selected: true,
      stale: false,
      value: "2025-04-30",
    },
    {
      available: true,
      cache_age_seconds: 172_800,
      detail: "EPSS probability evidence is stale.",
      last_error: "EPSS refresh failed",
      last_sync: "2025-04-28T09:55:00Z",
      name: "epss",
      selected: true,
      stale: true,
      value: "2025-04-28",
    },
    {
      available: false,
      cache_age_seconds: null,
      detail: "KEV catalog was selected but not available.",
      last_sync: null,
      name: "kev",
      selected: true,
      stale: false,
      value: null,
    },
  ],
  status: "degraded",
  warnings: ["EPSS source is stale", "KEV catalog cache is missing"],
}

test("providers route presents health-first data source diagnostics", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    providerStatus: degradedProviderStatus,
  })

  await page.goto("/providers")

  await expect(
    page.getByRole("heading", { level: 1, name: "Data Sources" }),
  ).toBeVisible()
  await expect(page.getByText("EPSS source is stale").first()).toBeVisible()
  await expect(page.getByText("KEV catalog cache is missing").first()).toBeVisible()
  await expect(page.getByText("Provider freshness").first()).toBeVisible()
  await expect(page.getByText("Needs sync").first()).toBeVisible()

  await expect(page.getByRole("tab", { name: "Sources" })).toHaveAttribute(
    "aria-selected",
    "true",
  )
  const sourcesTable = page.getByRole("table", {
    name: "Data source inventory",
  })
  await expect(sourcesTable).toContainText("NVD")
  await expect(sourcesTable).toContainText("EPSS")
  await expect(sourcesTable).toContainText("KEV")
  await expect(sourcesTable).toContainText("stale")
  await expect(sourcesTable).toContainText("missing")

  await page.getByRole("tab", { name: "Snapshot & Cache" }).click()
  await expect(page.getByText("Recorded snapshot").first()).toBeVisible()
  await expect(page.getByText("snapshot-2025-04-30").first()).toBeVisible()
  await expect(
    page.getByText("sha256:vpw-provider-snapshot").first(),
  ).toBeVisible()
  await expect(page.getByText("nvd-cache-hash").first()).toBeVisible()

  await page.getByRole("tab", { name: "Diagnostics" }).click()
  await expect(page.getByText("Latest provider update").first()).toBeVisible()
  await expect(page.getByText("provider-job-1").first()).toBeVisible()
  await expect(page.getByText("Provider runtime facts").first()).toBeVisible()
  await expect(page.getByText("/var/tmp/vpw/cache").first()).toBeVisible()
  await expect(page.getByText("/var/tmp/vpw/snapshots").first()).toBeVisible()
  await expect(page.getByText("EPSS source error").first()).toBeVisible()
  await expect(page.getByText("EPSS refresh failed").first()).toBeVisible()

  await page.getByRole("tab", { name: "Quality Notes" }).click()
  await expect(
    page.getByText("Provider data quality notes").first(),
  ).toBeVisible()
  await expect(page.getByText("EPSS source is stale").first()).toBeVisible()
  await expect(
    page.getByText("KEV catalog cache is missing").first(),
  ).toBeVisible()
})
