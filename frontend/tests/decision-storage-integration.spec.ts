import { createHash } from "node:crypto"
import { readFile } from "node:fs/promises"
import { gunzipSync } from "node:zlib"
import { expect, test } from "@playwright/test"
import { mockFinding, mockProject, routeWorkbenchShell } from "./workbench-route-mocks"
import { backendBaseUrl, localApiHeaders } from "./workbench-runtime-helpers"

test("pending daily decisions recover automatically without a manual reload", async ({ page }) => {
  await routeWorkbenchShell(page, { projects: [mockProject], findings: [mockFinding] })
  let reads = 0
  let ready = false
  await page.route(`**/api/v1/projects/${mockProject.id}/findings/?*`, (route) => {
    reads += 1
    return route.fulfill({
      contentType: "application/json",
      status: ready ? 200 : 503,
      body: JSON.stringify(!ready ? {
        detail: {
          code: "decision_refresh_pending",
          message: "Current decisions are awaiting today's governance update.",
        },
      } : { data: [mockFinding], count: 1 }),
    })
  })
  await page.goto(`/findings?projectId=${mockProject.id}`)
  await expect(page.getByText(/awaiting today's governance update/)).toBeVisible()
  ready = true
  await expect(page.getByRole("table", { name: "Findings remediation queue" }))
    .toContainText(mockFinding.cve_id, { timeout: 10_000 })
  expect(reads).toBeGreaterThanOrEqual(2)
})

test("compressed historical JSON can be generated and downloaded through the Evidence Center", async ({
  page,
}, testInfo) => {
  test.setTimeout(120_000)
  const seeded = await page.request.post(`${backendBaseUrl}/api/v1/workbench/demo`, {
    headers: localApiHeaders(),
    data: { reset: true },
  })
  expect(seeded.ok()).toBeTruthy()
  const demo = await seeded.json()
  const runId = demo.latest_run.id
  await page.goto(`/reports?projectId=${demo.project.id}&runId=${runId}`)
  await page.getByRole("button", { name: "Export compressed JSON", exact: true }).click()
  await page.getByRole("tab", { name: "History" }).click()
  const downloadButton = page.getByRole("button", { name: "Download analysis-result.v2.json.gz" })
  await expect(downloadButton).toBeVisible({ timeout: 30_000 })
  const downloading = page.waitForEvent("download")
  await downloadButton.click()
  const download = await downloading
  expect(download.suggestedFilename()).toBe("analysis-result.v2.json.gz")
  expect(await download.failure()).toBeNull()
  const path = testInfo.outputPath(download.suggestedFilename())
  await download.saveAs(path)
  const bytes = await readFile(path)
  const result = JSON.parse(gunzipSync(bytes).toString("utf-8"))
  expect(result.schema).toBe("analysis-result.v2")
  expect(result.analysis_run.id).toBe(runId)
  expect(result.findings.length).toBeGreaterThan(0)
  expect(result.findings.every((finding: { evidence: unknown }) => finding.evidence)).toBe(true)
  const response = await page.request.get(`${backendBaseUrl}/api/v1/runs/${runId}/reports`)
  const artifacts = await response.json()
  const report = artifacts.data.find((item: { format: string }) => item.format === "json-gzip")
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(report.sha256)
})
