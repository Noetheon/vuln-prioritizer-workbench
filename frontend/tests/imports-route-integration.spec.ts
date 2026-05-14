import { expect, test } from "@playwright/test"
import type { AnalysisRunPublic, AnalysisRunSummaryPublic } from "../src/api-client"
import { mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

const runOne = importRun("run-1", "historical-import-one.txt")
const runTwo = importRun("run-2", "historical-import-two.txt")

test("imports route deep links selected run and preserves it across reload", async ({
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

  await page.goto(`/imports?projectId=${mockProject.id}&runId=${runTwo.id}`)

  const runTwoRow = page.getByRole("row", {
    name: /historical-import-two\.txt/,
  })
  await expect(
    page.getByRole("cell", { name: "historical-import-two.txt" }),
  ).toBeVisible()
  await expect(runTwoRow).toContainText("4 finding(s)")
  await runTwoRow.getByRole("button", { name: "View diagnostics" }).click()
  const diagnostics = page.getByRole("dialog", { name: "Run diagnostics" })
  await expect(diagnostics).toContainText(runTwo.id)
  await expect(
    diagnostics.getByRole("link", { exact: true, name: "Evidence Center" }),
  ).toHaveAttribute("href", `/reports?projectId=${mockProject.id}&runId=${runTwo.id}`)
  await page.keyboard.press("Escape")

  await page.reload()

  await expect(page).toHaveURL(new RegExp(`runId=${runTwo.id}`))
  await expect(runTwoRow).toContainText("4 finding(s)")

  await page
    .getByRole("row", { name: /historical-import-one\.txt/ })
    .getByRole("button", { name: "View diagnostics" })
    .click()

  await expect(page).toHaveURL(new RegExp(`runId=${runOne.id}`))
  await expect(diagnostics).toContainText(runOne.id)
})

function importRun(id: string, filename: string): AnalysisRunPublic {
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
      input_upload: { filename },
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
