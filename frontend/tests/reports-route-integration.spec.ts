import { expect, test } from "@playwright/test"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ReportPublic,
} from "../src/api-client"
import { mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

const runId = "run-reports-1"
const reportHtml = report("report-html", "executive-report.html", "html")
const reportZip = report("report-zip", "evidence-bundle.zip", "zip")

test("Evidence Center separates artifacts, decision, manifest, history, and data quality into tabs", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    runSummaries: { [runId]: runSummary() },
    runs: [analysisRun()],
  })
  await page.route(`**/api/v1/runs/${runId}/reports`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ count: 2, data: [reportHtml, reportZip] }),
    }),
  )
  await page.route(`**/api/v1/runs/${runId}/reports?*`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ count: 2, data: [reportHtml, reportZip] }),
    }),
  )
  await page.route(`**/api/v1/reports/${reportZip.id}/verify`, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        id: "verification-1",
        report_id: reportZip.id,
        status: "succeeded",
        summary: { ok: true, verified_files: 2 },
      }),
    }),
  )

  await page.goto(`/reports?projectId=${mockProject.id}&runId=${runId}`)

  await expect(page.getByRole("heading", { name: "Evidence Center" })).toBeVisible()
  await expect(page.getByRole("tab", { name: "Artifacts" })).toHaveAttribute(
    "aria-selected",
    "true",
  )
  await expect(
    page.getByRole("heading", { name: "Generated artifacts" }),
  ).toBeVisible()
  await expect(
    page.getByRole("heading", { name: "Recommended artifacts" }),
  ).toBeVisible()
  await expect(page.getByRole("table", { name: "Report history list" })).toContainText(
    "evidence-bundle.zip",
  )
  await expect(page.getByText("Executive Decision")).toHaveCount(0)

  await page.getByRole("tab", { name: "Decision Summary" }).click()
  await expect(
    page.getByRole("heading", { exact: true, name: "Executive Decision" }),
  ).toBeVisible()
  await expect(page.getByText("Manifest metadata")).toHaveCount(0)

  await page.getByRole("tab", { name: "Manifest & Verification" }).click()
  await expect(page.getByText("Evidence lifecycle")).toBeVisible()
  await expect(page.getByText("Download Evidence ZIP")).toBeVisible()

  await page.getByRole("tab", { name: "History" }).click()
  await expect(page.getByRole("table", { name: "Report history list" })).toContainText(
    "executive-report.html",
  )

  await page.getByRole("tab", { name: "Data Quality" }).click()
  await expect(page.getByText("Parser errors")).toBeVisible()
  await expect(page.getByText("Ignored rows")).toBeVisible()
})

function analysisRun(): AnalysisRunPublic {
  return {
    filename: "reports-input.txt",
    finished_at: "2026-05-10T10:05:00Z",
    id: runId,
    input_type: "cve-list",
    project_id: mockProject.id,
    provider_snapshot_id: "demo",
    started_at: "2026-05-10T10:00:00Z",
    status: "succeeded",
    summary_json: { input_upload: { filename: "reports-input.txt" } },
  }
}

function runSummary(): AnalysisRunSummaryPublic {
  return {
    counts_by_priority: { critical: 1, high: 1 },
    created_findings: 2,
    filename: "reports-input.txt",
    finding_count: 2,
    finished_at: "2026-05-10T10:05:00Z",
    id: runId,
    ignored_lines: 1,
    input_type: "cve-list",
    input_upload: { filename: "reports-input.txt" },
    kev_hits: 1,
    parse_errors: [
      {
        error_type: "invalid_cve",
        field: "cve_id",
        input_type: "cve-list",
        line: 4,
        message: "Invalid CVE",
      },
    ],
    project_id: mockProject.id,
    provider_degraded: false,
    provider_snapshot_id: "demo",
    started_at: "2026-05-10T10:00:00Z",
    status: "succeeded",
    updated_findings: 0,
  }
}

function report(id: string, filename: string, format: string): ReportPublic {
  return {
    analysis_run_id: runId,
    content_type: format === "zip" ? "application/zip" : "text/html",
    created_at: "2026-05-10T10:10:00Z",
    download_url: `/api/v1/reports/${id}/download`,
    filename,
    format,
    id,
    kind: "evidence",
    metadata_json: {},
    project_id: mockProject.id,
    sha256: "a".repeat(64),
    size_bytes: 2048,
  }
}
