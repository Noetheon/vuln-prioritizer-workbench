import { expect, type Locator, type Page, test } from "@playwright/test"
import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "../src/api-client"
import { mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

const runOne = importRun("run-1", "historical-import-one.txt", 2)
const runTwo = importRun("run-2", "historical-import-two.txt", 4)

test("imports center opens run detail and diagnostics drawer", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runSummaries: {
      [runOne.id]: importRunSummary(runOne, 2),
      [runTwo.id]: importRunSummary(runTwo, 4),
    },
    runs: [runOne, runTwo],
  })
  await page.route(`**/api/v1/runs/${runTwo.id}/reports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: [], count: 0 }),
    }),
  )

  await page.goto(`/imports?projectId=${mockProject.id}`)
  await expect(page.getByRole("heading", { name: "Imports" }).first()).toBeVisible()
  await expect(page.getByRole("link", { name: /New import/ })).toHaveAttribute(
    "href",
    `/imports/new?projectId=${mockProject.id}`,
  )
  await expect(page.getByLabel("Evidence file")).toHaveCount(0)

  const runTwoRow = page.getByRole("row", {
    name: /historical-import-two\.txt/,
  })
  await expect(
    page.getByRole("cell", { name: "historical-import-two.txt" }),
  ).toBeVisible()
  await expect(runTwoRow).toContainText("4 finding(s)")

  await runTwoRow
    .getByRole("button", { name: "View diagnostics for run run-2" })
    .click()
  const diagnostics = page.getByRole("dialog", { name: "Run diagnostics" })
  await expect(diagnostics).toContainText(runTwo.id)
  for (const tab of ["Summary", "Parser", "Upload", "Provider", "Raw"]) {
    await expect(diagnostics.getByRole("tab", { name: tab })).toBeVisible()
  }
  await page.keyboard.press("Escape")

  await runTwoRow
    .getByRole("link", { name: "View details for run run-2" })
    .click()
  await expect(page).toHaveURL(
    `/imports/runs/${runTwo.id}?projectId=${mockProject.id}`,
  )
  await expect(
    page.getByRole("heading", { name: "Import run run-2" }),
  ).toBeVisible()
  for (const tab of ["Overview", "Findings", "Diagnostics", "Evidence", "Metadata"]) {
    await expect(page.getByRole("tab", { name: tab })).toBeVisible()
  }
  await expect(page.getByText("Evidence recorded")).toHaveCount(0)
  await expect(page.getByText("Optional context applied")).toHaveCount(0)

  await page.reload()
  await expect(page).toHaveURL(
    `/imports/runs/${runTwo.id}?projectId=${mockProject.id}`,
  )
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute(
    "aria-selected",
    "true",
  )
})

test("legacy imports runId search redirects to canonical run route", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runSummaries: {
      [runTwo.id]: importRunSummary(runTwo, 4),
    },
    runs: [runTwo],
  })
  await page.route(`**/api/v1/runs/${runTwo.id}/reports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: [], count: 0 }),
    }),
  )

  await page.goto(`/imports?projectId=${mockProject.id}&runId=${runTwo.id}`)
  await expect(page).toHaveURL(
    `/imports/runs/${runTwo.id}?projectId=${mockProject.id}`,
  )
  await expect(
    page.getByRole("heading", { name: "Import run run-2" }),
  ).toBeVisible()
})

test("new import wizard gates the four-step flow", async ({ page }) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
  })

  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await expect(
    page.getByRole("heading", { name: "New import" }),
  ).toBeVisible()
  await expect(page.getByRole("heading", { name: "Choose source" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Start import" })).toHaveCount(0)

  await page.getByRole("button", { name: /Generic occurrence CSV/ }).click()
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(page.getByRole("heading", { name: "Upload file" })).toBeVisible()
  await expect(page.getByText("Evidence file is required")).toBeVisible()
  await expect(page.getByText("Continue is unavailable until an evidence file is selected.")).toBeVisible()
  await expect(
    page.getByRole("button", {
      name: /Add context Upload a valid evidence file first\./,
    }),
  ).toBeDisabled()
  await expect(page.getByRole("button", { name: "Start import" })).toHaveCount(0)

  await page.getByLabel("Evidence file").setInputFiles({
    buffer: Buffer.from("cve_id\nCVE-2024-3094\n"),
    mimeType: "text/csv",
    name: "wizard-occurrences.csv",
  })
  await expect(page.getByText("File check passed").first()).toBeVisible()
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(page.getByRole("heading", { name: "Add context" })).toBeVisible()
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(page.getByRole("heading", { name: "Review import" })).toBeVisible()
  await expect(page.getByText("Project selected")).toBeVisible()
  await expect(page.getByRole("button", { name: "Start import" })).toBeVisible()
})

test("new import wizard keeps desktop and mobile layouts within the viewport", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
  })

  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await expect(
    page.getByRole("heading", { name: "New import" }),
  ).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await expectElementWithinViewport(page.getByTestId("import-summary-rail"))

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await expect(
    page.getByRole("heading", { name: "New import" }),
  ).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await page.getByTestId("import-summary-rail").scrollIntoViewIfNeeded()
  await expect(page.getByTestId("import-summary-rail")).toContainText("Import summary")
  await expectElementWithinViewport(page.getByTestId("import-summary-rail"))
})

test("run detail diagnostics drawer fills the mobile viewport without clipping", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runSummaries: {
      [runTwo.id]: importRunSummary(runTwo, 4),
    },
    runs: [runTwo],
  })
  await page.route(`**/api/v1/runs/${runTwo.id}/reports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: [], count: 0 }),
    }),
  )

  await page.goto(`/imports/runs/${runTwo.id}?projectId=${mockProject.id}`)
  await page.getByRole("button", { name: "Diagnostics" }).click()
  const dialog = page.getByRole("dialog", { name: "Run diagnostics" })
  await expect(dialog).toBeVisible()
  await expect
    .poll(() => drawerFitsMobileViewport(dialog), {
      message: "diagnostics drawer should settle inside the mobile viewport",
    })
    .toBe(true)
  const metrics = await drawerMetrics(dialog)
  expect(metrics.left).toBeGreaterThanOrEqual(0)
  expect(metrics.right).toBeLessThanOrEqual(metrics.viewportWidth + 1)
  expect(Math.abs(metrics.width - metrics.viewportWidth)).toBeLessThanOrEqual(2)
  await expectNoHorizontalOverflow(page)
})

test("supported formats search and category filters stay constrained", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
  })

  await page.goto(`/imports/formats?projectId=${mockProject.id}`)
  await expect(
    page.getByRole("heading", { name: "Supported formats" }),
  ).toBeVisible()
  await expect(page.getByText("OSV JSON")).toHaveCount(0)
  await expect(page.getByText("GHSA")).toHaveCount(0)
  await expect(page.getByText("Snyk")).toHaveCount(0)

  const formatsTable = page.getByRole("table", {
    name: "Supported import formats",
  })
  await expect(formatsTable.getByRole("row")).toHaveCount(11)
  await expect(formatsTable).toContainText("CycloneDX SBOM JSON")
  await page.getByRole("button", { name: "Nessus XML" }).click()
  await expect(page.getByText(/Workbench does not scan networks/)).toBeVisible()
  await page.getByRole("button", { name: "OpenVAS XML" }).click()
  await expect(page.getByText(/Parsed locally from supplied exports/)).toBeVisible()
  await page.getByLabel("Search formats").fill("nessus")
  await expect(formatsTable).toContainText("Nessus XML")
  await expect(formatsTable).not.toContainText("Trivy JSON")

  await page.getByLabel("Search formats").fill("")
  await page.getByRole("combobox", { name: "Category" }).click()
  await page.getByRole("option", { name: "SBOM / dependency data" }).click()
  await expect(formatsTable).toContainText("CycloneDX SBOM JSON")
  await expect(formatsTable).toContainText("SPDX SBOM JSON")
  await expect(formatsTable).not.toContainText("Nessus XML")

  await page.getByRole("button", { name: "CycloneDX SBOM JSON" }).click()
  await expect(page.getByText("plain SBOM-only BOM without vulnerabilities is not sufficient")).toBeVisible()
  await expect(
    page.getByRole("link", { name: "Start import with this format" }),
  ).toHaveAttribute(
    "href",
    `/imports/new?projectId=${mockProject.id}&inputType=cyclonedx-json`,
  )
})

async function expectNoHorizontalOverflow(page: Page) {
  const metrics = await page.evaluate(() => {
    const documentElement = document.documentElement
    return {
      bodyScrollWidth: document.body.scrollWidth,
      documentScrollWidth: documentElement.scrollWidth,
      viewportWidth: documentElement.clientWidth,
    }
  })
  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(metrics.viewportWidth + 1)
  expect(metrics.documentScrollWidth).toBeLessThanOrEqual(metrics.viewportWidth + 1)
}

async function expectElementWithinViewport(locator: Locator) {
  const metrics = await drawerMetrics(locator)
  expect(metrics.left).toBeGreaterThanOrEqual(0)
  expect(metrics.right).toBeLessThanOrEqual(metrics.viewportWidth + 1)
  expect(metrics.width).toBeLessThanOrEqual(metrics.viewportWidth + 1)
}

async function drawerFitsMobileViewport(locator: Locator) {
  const metrics = await drawerMetrics(locator)
  return (
    metrics.left >= 0 &&
    metrics.right <= metrics.viewportWidth + 1 &&
    Math.abs(metrics.width - metrics.viewportWidth) <= 2
  )
}

async function drawerMetrics(locator: Locator) {
  return locator.evaluate((element) => {
    const rect = element.getBoundingClientRect()
    return {
      left: rect.left,
      right: rect.right,
      viewportWidth: document.documentElement.clientWidth,
      width: rect.width,
    }
  })
}

function importRun(
  id: string,
  filename: string,
  findingCount: number,
): AnalysisRunPublic {
  return {
    filename,
    finished_at: "2026-05-10T10:05:00Z",
    id,
    input_type: "cve-list",
    project_id: mockProject.id,
    provider_snapshot_id: "demo",
    started_at: "2026-05-10T10:00:00Z",
    status: "succeeded",
    summary_json: {
      created_findings: findingCount,
      finding_count: findingCount,
      ignored_lines: 0,
      input_upload: { filename },
      updated_findings: 0,
    },
  }
}

function importRunSummary(
  run: AnalysisRunPublic,
  findingCount: number,
): AnalysisRunSummaryPublic {
  return {
    created_findings: findingCount,
    filename: run.filename ?? null,
    finding_count: findingCount,
    finished_at: run.finished_at ?? null,
    id: run.id,
    ignored_lines: 0,
    input_type: run.input_type,
    input_upload: { filename: run.filename },
    parse_errors: [],
    project_id: run.project_id,
    provider_degraded: false,
    provider_snapshot_id: run.provider_snapshot_id,
    started_at: run.started_at ?? "2026-05-10T10:00:00Z",
    status: run.status ?? "succeeded",
    updated_findings: 0,
  }
}
