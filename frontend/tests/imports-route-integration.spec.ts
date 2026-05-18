import { expect, type Locator, type Page, test } from "@playwright/test"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ReportPublic,
} from "../src/api-client"
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
  await expect(
    page.getByRole("heading", { name: "Imports" }).first(),
  ).toBeVisible()
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
    page.getByRole("heading", { name: "Import run run-2" }).first(),
  ).toBeVisible()
  for (const tab of [
    "Overview",
    "Review findings",
    "Diagnostics",
    "Evidence",
    "Metadata",
  ]) {
    await expect(page.getByRole("tab", { name: tab })).toBeVisible()
  }
  await expect(page.getByText("Evidence recorded")).toHaveCount(0)
  await expect(page.getByText("Optional context applied")).toHaveCount(0)
  await expect(page.getByText(/API does not expose/i)).toHaveCount(0)

  await page.reload()
  await expect(page).toHaveURL(
    `/imports/runs/${runTwo.id}?projectId=${mockProject.id}`,
  )
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute(
    "aria-selected",
    "true",
  )
})

test("run detail tabs show triage CTA, imported evidence, and compact diagnostics metadata", async ({
  page,
}) => {
  const runWithMetadata = importRun("run-detail-rich", "rich-import.txt", 4)
  const summaryWithMetadata = importRunSummary(runWithMetadata, 4)
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runSummaries: {
      [runWithMetadata.id]: summaryWithMetadata,
    },
    runs: [runWithMetadata],
  })
  await page.route(`**/api/v1/runs/${runWithMetadata.id}/reports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: [], count: 0 }),
    }),
  )

  await page.goto(`/imports/runs/${runWithMetadata.id}?projectId=${mockProject.id}`)
  await page.getByRole("tab", { name: "Review findings" }).click()
  await expect(page.getByText("Findings are ready for triage")).toBeVisible()
  await expect(page.getByRole("link", { name: "Open Triage" })).toHaveAttribute(
    "href",
    `/findings?projectId=${mockProject.id}`,
  )
  await expect(page.getByText(/API does not expose/i)).toHaveCount(0)

  await page.getByRole("tab", { name: "Evidence" }).click()
  await expect(page.getByText("Imported evidence")).toBeVisible()
  await expect(page.getByText("rich-import.txt", { exact: true })).toBeVisible()
  await expect(page.getByText("sha256-rich-import")).toBeVisible()
  await expect(page.getByText("No report artifacts generated yet")).toBeVisible()
  for (const artifact of [
    "Technical Markdown",
    "Executive HTML",
    "Analysis JSON",
    "Findings CSV",
    "SARIF",
    "Evidence ZIP",
    "ATT&CK Navigator layer, if mapped",
  ]) {
    await expect(page.getByText(artifact)).toBeVisible()
  }
  await expect(
    page.getByRole("link", { name: "Open Evidence Center" }),
  ).toHaveAttribute("href", `/reports?projectId=${mockProject.id}&runId=${runWithMetadata.id}`)

  await page.getByRole("tab", { name: "Diagnostics" }).click()
  await expect(page.getByText("Parser diagnostics")).toBeVisible()
  await expect(page.getByText("Rows read")).toBeVisible()
  await expect(page.getByText("Upload and provider")).toBeVisible()
  await expect(
    page.getByText("storage://imports/rich-import.txt", { exact: true }),
  ).toBeVisible()

  await page.getByRole("tab", { name: "Metadata" }).click()
  await expect(page.getByRole("button", { name: "Copy run ID" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Copy SHA256" })).toBeVisible()
  await expect(page.getByText("Raw metadata")).toBeVisible()
})

test("run detail evidence only verifies evidence bundles", async ({ page }) => {
  const runWithReports = importRun("run-with-reports", "reports-import.txt", 4)
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runSummaries: {
      [runWithReports.id]: importRunSummary(runWithReports, 4),
    },
    runs: [runWithReports],
  })
  await page.route(`**/api/v1/runs/${runWithReports.id}/reports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        count: 2,
        data: [
          reportArtifact(runWithReports, "csv-report", "csv", "report", "findings.csv"),
          reportArtifact(
            runWithReports,
            "zip-report",
            "zip",
            "evidence-bundle",
            "evidence-bundle.zip",
          ),
        ],
      }),
    }),
  )

  await page.goto(`/imports/runs/${runWithReports.id}?projectId=${mockProject.id}`)
  await page.getByRole("tab", { name: "Evidence" }).click()
  await expect(
    page.getByRole("heading", { name: "Generated report artifacts" }),
  ).toBeVisible()
  await expect(
    page.getByRole("button", { name: "Download findings.csv" }),
  ).toBeVisible()
  await expect(
    page.getByRole("button", { name: "Verify findings.csv" }),
  ).toHaveCount(0)
  await expect(
    page.getByRole("button", { name: "Download evidence-bundle.zip" }),
  ).toBeVisible()
  await expect(
    page.getByRole("button", { name: "Verify evidence-bundle.zip" }),
  ).toBeVisible()
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
    page.getByRole("heading", { name: "Import run run-2" }).first(),
  ).toBeVisible()
})

test("new import wizard gates the four-step flow", async ({ page }) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
  })

  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await expect(page.getByRole("heading", { name: "New import" })).toBeVisible()
  await expect(
    page.getByRole("heading", { name: "Choose source" }),
  ).toBeVisible()
  await expect(page.getByTestId("import-summary-rail")).toContainText(
    "Needs input type",
  )
  await expect(page.getByRole("button", { name: "Start import" })).toHaveCount(
    0,
  )

  await page.getByRole("button", { name: /Generic occurrence CSV/ }).click()
  await expect(page.getByTestId("import-summary-rail")).toContainText(
    "Can continue",
  )
  await expect(page.getByTestId("import-wizard-command-bar")).not.toContainText(
    "Selected",
  )
  await expect(page.getByTestId("import-wizard-command-bar")).not.toContainText(
    "Generic occurrence CSV",
  )
  await expect(
    page.getByTestId("import-summary-rail").locator("dt"),
  ).toHaveText([
    "Project",
    "Input type",
    "Evidence file",
    "Asset context",
    "VEX",
    "ATT&CK context",
    "Provider data",
    "Deterministic replay",
    "Readiness",
  ])
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(page.getByRole("heading", { name: "Upload file" })).toBeVisible()
  await expect(page.getByText("Evidence file is required")).toBeVisible()
  await expect(
    page.getByText(
      "Continue is unavailable until an evidence file is selected.",
    ),
  ).toBeVisible()
  await expect(
    page.getByRole("button", {
      name: /Add context Upload evidence first\./,
    }),
  ).toBeDisabled()
  await expect(page.getByTestId("import-summary-rail")).toContainText(
    "Needs evidence file",
  )
  await expect(page.getByRole("button", { name: "Start import" })).toHaveCount(
    0,
  )

  await page.getByLabel("Evidence file").setInputFiles({
    buffer: Buffer.from("cve_id\nCVE-2024-3094\n"),
    mimeType: "text/csv",
    name: "wizard-occurrences.csv",
  })
  await expect(page.getByText("B. File check")).toBeVisible()
  await expect(page.getByText("Parser preview")).toBeVisible()
  await expect(page.getByText("Accepted file types:")).toHaveCount(0)
  await expect(page.getByText("Accepted: .csv, text/csv")).toHaveCount(0)
  await expect(page.getByText("File type match")).toBeVisible()
  await expect(
    page.getByText(
      "If the file structure does not match the selected format, import may create fewer findings or skip rows.",
    ),
  ).toBeVisible()
  await expect(page.getByRole("button", { name: "Remove" })).toBeVisible()
  await expect(page.getByTestId("import-summary-rail")).toContainText(
    "Can continue",
  )
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(page.getByRole("heading", { name: "Add context" })).toBeVisible()
  await expect(page.getByTestId("import-summary-rail")).toContainText(
    "Can continue",
  )
  await expect(page.getByLabel("ATT&CK source")).toBeHidden()
  await page
    .getByText("Advanced provider data and reviewed ATT&CK context")
    .click()
  await expect(page.getByLabel("ATT&CK source")).toBeVisible()
  await expect(
    page.getByLabel("Lock provider data for deterministic replay"),
  ).not.toBeChecked()
  await page.getByLabel("ATT&CK source").click()
  await page.getByRole("option", { name: "Local curated" }).click()
  await expect(page.getByText("ATT&CK context needs attention")).toBeVisible()
  await expect(page.getByRole("button", { name: "Continue" })).toBeDisabled()
  await page.getByLabel("Mapping file").fill("mapping.json")
  await expect(page.getByText("ATT&CK context needs attention")).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Continue" })).toBeEnabled()
  await page.getByLabel("Asset context CSV").setInputFiles({
    buffer: Buffer.from("not csv"),
    mimeType: "text/plain",
    name: "asset-context.txt",
  })
  await expect(page.getByText("Asset context file needs attention")).toBeVisible()
  await expect(page.getByRole("button", { name: "Continue" })).toBeDisabled()
  await page.getByRole("button", { name: "Remove" }).click()
  await page.getByLabel("VEX overlay").setInputFiles({
    buffer: Buffer.from("{"),
    mimeType: "application/json",
    name: "bad-vex.json",
  })
  await expect(page.getByText("Invalid VEX overlay JSON.")).toBeVisible()
  await expect(page.getByRole("button", { name: "Continue" })).toBeDisabled()
  await page.getByRole("button", { name: "Remove" }).click()
  await page.getByRole("button", { name: "Continue" }).click()
  await expect(
    page.getByRole("heading", { name: "Review import" }),
  ).toBeVisible()
  await expect(page.getByTestId("import-summary-rail")).toContainText(
    "Ready to import",
  )
  await expect(
    page.getByRole("heading", { name: "Preflight checks" }),
  ).toBeVisible()
  await expect(page.getByText("Updates expected")).toHaveCount(0)
  await expect(page.getByText("Updated findings")).toBeVisible()
  await expect(
    page.getByText("Available after import", { exact: true }).first(),
  ).toBeVisible()
  await expect(page.getByRole("button", { name: "Start import" })).toBeVisible()
})

test("new import failure without run id stays on review with retry and back actions", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
  })
  await page.route(`**/api/v1/projects/${mockProject.id}/imports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      status: 400,
      body: JSON.stringify({ detail: "Parser rejected the supplied evidence." }),
    }),
  )

  await completeWizardToReview(page)
  await page.getByRole("button", { name: "Start import" }).click()

  await expect(page).toHaveURL(`/imports/new?projectId=${mockProject.id}`)
  await expect(page.getByRole("alert").getByText("Import failed")).toBeVisible()
  await expect(page.getByTestId("import-summary-rail")).toContainText("Failed")
  await expect(page.getByTestId("import-summary-rail")).not.toContainText(
    "Ready to import",
  )
  await expect(page.getByRole("button", { name: "Retry import" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Back to file" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Start import" })).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Open diagnostics" })).toHaveCount(
    0,
  )
  await expect(page.getByRole("link", { name: "Open run detail" })).toHaveCount(0)
})

test("new import failure with run id stays on review and exposes diagnostics", async ({
  page,
}) => {
  const failedRun = {
    ...importRun("failed-run", "failed-import.csv", 0),
    error_json: { message: "Parser rejected the supplied evidence." },
    error_message: "Parser rejected the supplied evidence.",
    status: "failed",
  } satisfies AnalysisRunPublic
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runSummaries: {
      [failedRun.id]: {
        ...importRunSummary(failedRun, 0),
        parse_errors: [
          {
            error_type: "parser",
            input_type: failedRun.input_type,
            message: "Invalid row 2",
          },
        ],
        status: "failed",
      },
    },
    runs: [failedRun],
  })
  await page.route(`**/api/v1/projects/${mockProject.id}/imports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      status: 400,
      body: JSON.stringify({
        detail: {
          analysis_run_id: failedRun.id,
          message: "Parser rejected the supplied evidence.",
          parse_errors: [
            {
              error_type: "parser",
              input_type: failedRun.input_type,
              message: "Invalid row 2",
            },
          ],
        },
      }),
    }),
  )

  await completeWizardToReview(page)
  await page.getByRole("button", { name: "Start import" }).click()

  await expect(page).toHaveURL(`/imports/new?projectId=${mockProject.id}`)
  await expect(page.getByRole("alert").getByText("Import failed")).toBeVisible()
  await expect(page.getByTestId("import-summary-rail")).toContainText("Failed")
  await expect(page.getByTestId("import-summary-rail")).not.toContainText(
    "Ready to import",
  )
  await expect(page.getByRole("button", { name: "Retry import" })).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Start import" })).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Back to file" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Open diagnostics" })).toBeVisible()
  await expect(page.getByRole("link", { name: "Open run detail" })).toHaveAttribute(
    "href",
    `/imports/runs/${failedRun.id}?projectId=${mockProject.id}`,
  )
  await page.getByRole("button", { name: "Open diagnostics" }).click()
  await expect(page.getByRole("dialog", { name: "Run diagnostics" })).toContainText(
    failedRun.id,
  )
})

test("new import wizard keeps desktop and mobile layouts within the viewport", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
  })

  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await expect(page.getByRole("heading", { name: "New import" })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await expectElementWithinViewport(page.getByTestId("import-summary-rail"))

  await page.setViewportSize({ width: 1470, height: 956 })
  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await expect(page.getByRole("heading", { name: "New import" })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  const macbookLayoutBox = await page.locator(".imports-wizard-layout").boundingBox()
  const macbookSummaryBox = await page
    .getByTestId("import-summary-rail")
    .boundingBox()
  const commandBarBox = await page
    .getByTestId("import-wizard-command-bar")
    .boundingBox()
  expect(macbookLayoutBox).not.toBeNull()
  expect(macbookSummaryBox).not.toBeNull()
  expect(commandBarBox).not.toBeNull()
  expect(
    Math.abs((macbookSummaryBox?.y ?? 0) - (macbookLayoutBox?.y ?? 0)),
  ).toBeLessThanOrEqual(1)
  expect(macbookSummaryBox?.x ?? 0).toBeGreaterThan(
    (macbookLayoutBox?.x ?? 0) + 600,
  )
  expect(commandBarBox?.y ?? 0).toBeGreaterThanOrEqual(0)
  expect((commandBarBox?.y ?? 0) + (commandBarBox?.height ?? 0)).toBeLessThanOrEqual(
    956 + 1,
  )

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`/imports/new?projectId=${mockProject.id}`)
  await expect(page.getByRole("heading", { name: "New import" })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await page.getByTestId("import-summary-rail").scrollIntoViewIfNeeded()
  await expect(page.getByTestId("import-summary-rail")).toContainText(
    "Import summary",
  )
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
  const tabMetrics = await dialog
    .getByRole("tablist", { name: "Run diagnostics tabs" })
    .evaluate((element) => {
      const rect = element.getBoundingClientRect()
      return {
        height: rect.height,
        scrollWidth: element.scrollWidth,
        width: rect.width,
      }
    })
  expect(tabMetrics.height).toBeLessThanOrEqual(48)
  expect(tabMetrics.scrollWidth).toBeGreaterThanOrEqual(tabMetrics.width)
  await expect(dialog.getByRole("link", { name: "Review findings" })).toBeVisible()
  await expect(dialog.getByRole("link", { name: "Open run detail" })).toBeVisible()
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
  await expect(
    page.getByText(/Parsed locally from supplied exports/),
  ).toBeVisible()
  await page.getByLabel("Search formats").fill("nessus")
  await expect(formatsTable).toContainText("Nessus XML")
  await expect(formatsTable).not.toContainText("Trivy JSON")
  await expect(page.getByRole("heading", { name: "Nessus XML" })).toBeVisible()
  await expect(page.getByText(/Workbench does not scan networks/)).toBeVisible()

  await page.getByLabel("Search formats").fill("definitely-not-supported")
  await expect(
    page.getByText('No supported format matches "definitely-not-supported".'),
  ).toBeVisible()
  await expect(page.getByRole("heading", { name: "Nessus XML" })).toHaveCount(0)
  await page.getByRole("button", { name: "Clear search" }).click()
  await expect(formatsTable.getByRole("row")).toHaveCount(11)

  await page.getByLabel("Search formats").fill("")
  await page.getByRole("combobox", { name: "Category" }).click()
  await page.getByRole("option", { name: "SBOM / dependency data" }).click()
  await expect(formatsTable).toContainText("CycloneDX SBOM JSON")
  await expect(formatsTable).toContainText("SPDX SBOM JSON")
  await expect(formatsTable).not.toContainText("Nessus XML")
  await expect(
    page.getByRole("heading", { name: "CycloneDX SBOM JSON" }),
  ).toBeVisible()

  await page.getByRole("button", { name: "CycloneDX SBOM JSON" }).click()
  await expect(page.getByRole("button", { name: "View details" }).first()).toBeVisible()
  await expect(
    page.getByRole("cell", { name: "component vulnerability context" }),
  ).toBeVisible()
  await expect(page.getByText("vex capable")).toHaveCount(0)
  await expect(
    page.getByText(
      "plain SBOM-only BOM without vulnerabilities is not sufficient",
    ),
  ).toBeVisible()
  await expect(formatsTable).not.toContainText('{"bomFormat"')
  await expect(page.getByRole("button", { name: "Copy example" })).toBeVisible()
  await expect(
    page.getByRole("link", { name: "Start import with this format" }),
  ).toHaveAttribute(
    "href",
    `/imports/new?projectId=${mockProject.id}&input_type=cyclonedx-json`,
  )
})

async function completeWizardToReview(page: Page) {
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
  await expect(page.getByRole("heading", { name: "Review import" })).toBeVisible()
}

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
  expect(metrics.documentScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
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
      input_upload: {
        filename,
        sha256: `sha256-${filename.replace(".txt", "")}`,
        storage_ref: `storage://imports/${filename}`,
      },
      rows_read: findingCount,
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
    input_upload: {
      filename: run.filename,
      sha256: `sha256-${(run.filename ?? "upload").replace(".txt", "")}`,
      storage_ref: `storage://imports/${run.filename ?? "upload"}`,
    },
    parse_errors: [],
    project_id: run.project_id,
    provider_degraded: false,
    provider_snapshot_id: run.provider_snapshot_id,
    started_at: run.started_at ?? "2026-05-10T10:00:00Z",
    status: run.status ?? "succeeded",
    updated_findings: 0,
  }
}

function reportArtifact(
  run: AnalysisRunPublic,
  id: string,
  format: string,
  kind: string,
  filename: string,
): ReportPublic {
  return {
    analysis_run_id: run.id,
    content_type: format === "zip" ? "application/zip" : "text/csv",
    created_at: "2026-05-10T10:10:00Z",
    download_url: `/api/v1/reports/${id}/download`,
    filename,
    format,
    id,
    kind,
    project_id: run.project_id,
    sha256: `sha256-${id}`,
    size_bytes: 1234,
  }
}
