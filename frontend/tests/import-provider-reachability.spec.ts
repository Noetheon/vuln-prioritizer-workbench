import { expect, type Page, test } from "@playwright/test"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProviderStatusPublic,
} from "../src/api-client"
import { mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

const liveProviderStatus: ProviderStatusPublic = {
  cache_age_seconds: null,
  import_provider_mode: "live",
  last_sync: null,
  snapshot: { missing: true, mode: "live" },
  snapshot_mode: "live",
  sources: [],
  stale_after_hours: 72,
  status: "not_loaded",
  warnings: [],
}

async function reachReview(page: Page) {
  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await page.getByRole("button", { name: /Generic occurrence CSV/ }).click()
  await page.getByRole("button", { name: "Continue" }).click()
  await page.getByLabel("Evidence file").setInputFiles({
    buffer: Buffer.from("cve_id\nCVE-2024-3094\n"),
    mimeType: "text/csv",
    name: "wizard-occurrences.csv",
  })
  await expect(page.getByText("Parser preview")).toBeVisible()
  await page.getByRole("button", { name: "Continue" }).click()
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(
    page.getByRole("heading", { name: "Review import" }),
  ).toBeVisible()
}

test("a live import warns before it starts when feeds do not answer", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    providerReachability: {
      checked_at: "2026-06-06T10:00:00Z",
      sources: [
        { detail: "Timed out", label: "NVD", reachable: false, source: "nvd" },
        { detail: "HTTP 403", label: "EPSS", reachable: false, source: "epss" },
        { label: "KEV", reachable: true, source: "kev" },
      ],
    },
    providerStatus: liveProviderStatus,
  })

  await reachReview(page)

  await expect(
    page
      .getByRole("status")
      .filter({ hasText: "Provider data needs attention" }),
  ).toContainText(
    "NVD (Timed out) and EPSS (HTTP 403) do not answer from this Workbench. The import still runs, but CVSS scores and descriptions will be missing and priorities will be computed without EPSS. To import without live data, enter a provider snapshot under Add context.",
  )
  await expect(page.getByText("Provider data warning")).toBeVisible()
  // A warning, not a blocker: the import can still start.
  await expect(page.getByRole("button", { name: "Start import" })).toBeEnabled()
})

test("an import with a default snapshot does not probe the live feeds", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    providerStatus: {
      ...liveProviderStatus,
      import_provider_mode: "default_snapshot",
      snapshot: { missing: false, mode: "demo" },
      snapshot_mode: "demo",
      status: "ok",
    },
  })
  let probes = 0
  page.on("request", (request) => {
    if (request.url().includes("/api/v1/providers/reachability")) probes += 1
  })

  await reachReview(page)

  await expect(
    page.getByRole("definition").filter({ hasText: "Default provider snapshot" }),
  ).toHaveCount(2)
  await expect(page.getByText("Provider data ready")).toBeVisible()
  await expect(page.getByText("Provider data needs attention")).toHaveCount(0)
  expect(probes).toBe(0)
})

test("a run scored without complete provider data says what is missing", async ({
  page,
}) => {
  const run: AnalysisRunPublic = {
    filename: "cves.txt",
    finished_at: "2026-06-06T10:05:00Z",
    id: "run-degraded",
    input_type: "cve-list",
    project_id: mockProject.id,
    provider_snapshot_id: null,
    started_at: "2026-06-06T10:00:00Z",
    status: "succeeded",
  }
  const summary: AnalysisRunSummaryPublic = {
    created_findings: 2,
    filename: run.filename ?? null,
    finding_count: 2,
    finished_at: run.finished_at ?? null,
    id: run.id,
    input_type: run.input_type,
    parse_errors: [],
    project_id: mockProject.id,
    provider_degraded: true,
    provider_warnings: [
      "EPSS could not be reached for 2 CVEs, so their priorities were computed without EPSS.",
    ],
    started_at: run.started_at,
    status: "succeeded",
    warnings: [
      "EPSS could not be reached for 2 CVEs, so their priorities were computed without EPSS.",
    ],
  }
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runSummaries: { [run.id]: summary },
    runs: [run],
  })
  await page.route(`**/api/v1/runs/${run.id}/reports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ count: 0, data: [] }),
    }),
  )

  await page.goto(`/imports/runs/${run.id}?projectId=${mockProject.id}`)

  const banner = page
    .getByRole("status")
    .filter({ hasText: "Provider data was incomplete for this import" })
  await expect(banner).toContainText(
    "EPSS could not be reached for 2 CVEs, so their priorities were computed without EPSS.",
  )
  await expect(banner).toContainText(
    "Affected findings can rank lower than they should.",
  )
  await expect(
    banner.getByRole("link", { name: "Open Data Sources" }),
  ).toHaveAttribute("href", /\/data-sources/)
})
