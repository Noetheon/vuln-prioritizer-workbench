import { expect, test } from "@playwright/test"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
} from "../src/api-client"
import { mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

const run: AnalysisRunPublic = {
  id: "sbom-run",
  project_id: mockProject.id,
  input_type: "cyclonedx-json",
  filename: "inventory.json",
  provider_snapshot_id: "demo",
  status: "succeeded",
  started_at: "2026-09-19T10:00:00Z",
  finished_at: "2026-09-19T10:00:10Z",
  counts: { finding_count: 0, created_findings: 0, updated_findings: 0 },
}

function summary(
  status: "complete" | "partial" = "complete",
): AnalysisRunSummaryPublic {
  return {
    id: run.id,
    project_id: run.project_id,
    input_type: run.input_type,
    filename: "inventory.json",
    status: "succeeded",
    started_at: run.started_at ?? "2026-09-19T10:00:00Z",
    finished_at: run.finished_at ?? null,
    finding_count: 0,
    evidence: {
      analysis_run_id: run.id,
      project_id: run.project_id,
      input_type: run.input_type,
      status: "succeeded",
      analysis_semantics: {
        analysis_decision_scope: "project",
        persistence_scope: "project",
        finding_dedup_key_version: "v2",
      },
      analysis_service: {
        engine: "workbench",
        kernel: "v2",
        pipeline: "import",
      },
      sbom_assessment: {
        schema_version: "sbom-assessment.v1",
        scanner: "grype",
        scanner_version: "0.110.0",
        database_built_at: "2026-09-19T08:00:00Z",
        database_sha256: "d".repeat(64),
        scanned_at: "2026-09-19T10:00:10Z",
        observed_at: "2026-09-18T10:00:00Z",
        input_sha256: "a".repeat(64),
        output_sha256: "b".repeat(64),
        target_ref: "payments@1.0",
        target_kind: "sbom",
        input_format: "cyclonedx-json",
        component_count: 3,
        identified_component_count: status === "partial" ? 2 : 3,
        version_missing_count: status === "partial" ? 1 : 0,
        scanner_match_count: 0,
        prioritized_match_count: 0,
        unassigned_match_count: 0,
        warnings:
          status === "partial" ? ["One component is missing its version."] : [],
        status,
        artifact_refs: {},
      },
    },
  }
}

test("inventory upload requires an explicit scan and subject, preserving offline database choice", async ({
  page,
}) => {
  const browserErrors: string[] = []
  page.on("pageerror", (error) => browserErrors.push(error.message))
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text())
  })
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runs: [run],
    runSummaries: { [run.id]: summary() },
  })
  let submitted = ""
  await page.route(`**/api/v1/projects/${mockProject.id}/imports`, (route) => {
    submitted = route.request().postData() ?? ""
    return route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify(run),
    })
  })
  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await expect(page).toHaveTitle(/Vuln Prioritizer Workbench/)
  await expect(page.locator("vite-error-overlay")).toHaveCount(0)
  await page.getByRole("button", { name: /CycloneDX SBOM JSON/ }).click()
  await page.getByRole("button", { name: "Continue" }).click()
  await page.getByLabel("Evidence file").setInputFiles({
    name: "inventory.json",
    mimeType: "application/json",
    buffer: Buffer.from(
      '{"bomFormat":"CycloneDX","components":[{"name":"example","version":"1.0","purl":"pkg:npm/example@1.0"}]}',
    ),
  })
  await expect(
    page.getByText(/No vulnerability records are present/),
  ).toBeVisible()
  const scan = page.getByRole("checkbox", { name: /Scan SBOM with Grype/ })
  await expect(scan).not.toBeChecked()
  await scan.check()
  await expect(page.getByRole("button", { name: "Continue" })).toBeDisabled()
  await page.getByLabel("SBOM subject", { exact: true }).fill("payments@1.0")
  await page
    .getByRole("checkbox", { name: /Allow vulnerability database updates/ })
    .uncheck()
  await page.getByRole("button", { name: "Continue" }).click()
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(page.getByTestId("import-summary-rail")).toContainText("Grype")
  await expect(page.getByTestId("import-summary-rail")).toContainText(
    "Disabled",
  )
  await page.getByRole("button", { name: "Start import" }).click()
  await expect(page).toHaveURL(
    `/imports/runs/${run.id}?projectId=${mockProject.id}`,
  )
  expect(submitted).toContain('name="sbom_scanner"\r\n\r\ngrype')
  expect(submitted).toContain('name="sbom_target_ref"\r\n\r\npayments@1.0')
  expect(submitted).toContain('name="sbom_db_update"\r\n\r\nfalse')
  await expect(
    page.getByText("SBOM scan completed with no matches", { exact: true }),
  ).toBeVisible()
  expect(browserErrors).toEqual([])
})

test("partial zero-match scan keeps coverage limitations visible and rescan failures actionable", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runs: [run],
    runSummaries: { [run.id]: summary("partial") },
  })
  let rescanBody: unknown
  await page.route(`**/api/v1/runs/${run.id}/sbom-rescans`, (route) => {
    rescanBody = route.request().postDataJSON()
    return route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Grype is not available." }),
    })
  })
  await page.route(`**/api/v1/runs/${run.id}/sbom-evidence`, (route) =>
    route.fulfill({
      contentType: "application/zip",
      body: Buffer.from("fixture evidence ZIP"),
    }),
  )
  await page.goto(`/imports/runs/${run.id}?projectId=${mockProject.id}`)
  const downloadEvent = page.waitForEvent("download")
  await page.getByRole("button", { name: "Download SBOM evidence" }).click()
  expect((await downloadEvent).suggestedFilename()).toBe(
    `sbom-evidence-${run.id}.zip`,
  )
  await expect(
    page.getByText("SBOM assessment is partial", { exact: true }),
  ).toBeVisible()
  await expect(
    page.getByText("One component is missing its version."),
  ).toBeVisible()
  await expect(
    page.getByText("SBOM scan completed with no matches", { exact: true }),
  ).toHaveCount(0)
  await page.getByText("Scan provenance", { exact: true }).click()
  await expect(page.getByText("d".repeat(64), { exact: true })).toBeVisible()
  await page
    .getByRole("checkbox", { name: "Allow database downloads for this rescan" })
    .uncheck()
  await page.getByRole("button", { name: "Rescan saved SBOM" }).click()
  await expect(
    page.getByText("SBOM rescan could not start", { exact: true }),
  ).toBeVisible()
  expect(rescanBody).toEqual({ sbom_db_update: false })
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true)
})

test("rescan opens a new run and retains the inventory observation time", async ({
  page,
}) => {
  const rescan = {
    ...run,
    id: "sbom-rescan",
    started_at: "2026-09-20T10:00:00Z",
  }
  const originalSummary = summary()
  const newSummary: AnalysisRunSummaryPublic = {
    ...originalSummary,
    id: rescan.id,
    started_at: rescan.started_at,
    evidence: {
      ...originalSummary.evidence!,
      analysis_run_id: rescan.id,
      sbom_assessment: {
        ...originalSummary.evidence!.sbom_assessment!,
        source_run_id: run.id,
        scanned_at: "2026-09-20T10:00:10Z",
      },
    },
  }
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runs: [rescan, run],
    runSummaries: { [run.id]: originalSummary, [rescan.id]: newSummary },
  })
  let queued = false
  await page.route(/\/api\/v1\/projects\/[^/]+\/runs\/(?:\?.*)?$/, (route) => {
    const runs = queued ? [rescan, run] : [run]
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: runs, count: runs.length }),
    })
  })
  let rescanBody: unknown
  await page.route(`**/api/v1/runs/${run.id}/sbom-rescans`, (route) => {
    rescanBody = route.request().postDataJSON()
    queued = true
    return route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify(rescan),
    })
  })
  await page.goto(`/imports/runs/${run.id}?projectId=${mockProject.id}`)
  await page.getByRole("button", { name: "Rescan saved SBOM" }).click()
  await expect(page).toHaveURL(
    `/imports/runs/${rescan.id}?projectId=${mockProject.id}`,
  )
  expect(rescanBody).toEqual({ sbom_db_update: true })
  await page.getByText("Scan provenance", { exact: true }).click()
  await expect(page.getByText(run.id, { exact: true })).toBeVisible()
  await expect(
    page.getByText("Inventory observed", { exact: true }),
  ).toBeVisible()
  await expect(page.getByText(/Sep 18, 2026.*10:00/)).toBeVisible()
})
