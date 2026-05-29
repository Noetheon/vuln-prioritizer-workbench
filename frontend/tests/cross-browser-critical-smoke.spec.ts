import { readFile } from "node:fs/promises"
import { expect, test } from "@playwright/test"
import {
  backendBaseUrl,
  localApiHeaders,
  openWorkbench,
} from "./workbench-runtime-helpers"
import { validCveList, waitForRunSucceeded } from "./workbench-e2e-helpers"

test("critical Workbench evidence flow works across browser engines", async ({
  page,
}, testInfo) => {
  test.setTimeout(120_000)
  const headers = localApiHeaders()
  const suffix = `${testInfo.project.name}-${Date.now().toString(36)}`

  await openWorkbench(page)
  await expect(
    page.getByRole("heading", { exact: true, level: 1, name: "Overview" }),
  ).toBeVisible()

  const projectResponse = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/`,
    {
      data: {
        description: "Cross-browser critical evidence smoke",
        name: `Cross Browser Smoke ${suffix}`,
      },
      headers,
    },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string; name: string }

  const importResponse = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/${project.id}/imports`,
    {
      headers,
      multipart: {
        file: {
          buffer: validCveList,
          mimeType: "text/plain",
          name: "critical-smoke-cves.txt",
        },
        input_type: "cve-list",
        locked_provider_data: "true",
        provider_snapshot_file: "demo_provider_snapshot.json",
      },
    },
  )
  expect(importResponse.ok()).toBeTruthy()
  const queuedRun = (await importResponse.json()) as { id: string; status: string }
  expect(["pending", "running", "succeeded", "completed"]).toContain(queuedRun.status)
  const run = await waitForRunSucceeded(page, queuedRun.id, {
    apiBaseUrl: backendBaseUrl,
    headers,
  })

  await page.goto(`/reports?projectId=${project.id}&runId=${run.id}`)
  await expect(
    page.getByRole("heading", { level: 1, name: "Evidence Center" }),
  ).toBeVisible()
  await expect(
    page.getByRole("heading", { name: "Recommended artifacts" }),
  ).toBeVisible()

  const reports = [
    { action: "Export analysis JSON", filename: "analysis-result.v1.json" },
    { action: "Build evidence ZIP", filename: "evidence-bundle.zip" },
  ]
  for (const report of reports) {
    await page.getByRole("button", { name: report.action }).click()
    await expect(page.getByText(report.filename).first()).toBeVisible()
  }

  const reportHistory = page.getByRole("table", { name: "Report history list" })
  for (const report of reports) {
    const downloadPromise = page.waitForEvent("download")
    await reportHistory
      .getByRole("button", { name: `Download ${report.filename}` })
      .click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toBe(report.filename)
    expect(await download.failure()).toBeNull()

    const targetPath = testInfo.outputPath(
      `${testInfo.project.name}-${report.filename}`,
    )
    await download.saveAs(targetPath)
    const bytes = await readFile(targetPath)
    expect(bytes.byteLength).toBeGreaterThan(0)
    if (report.filename.endsWith(".json")) {
      const payload = JSON.parse(bytes.toString("utf-8")) as { schema: string }
      expect(payload.schema).toBe("analysis-result.v1")
    } else {
      expect(bytes.subarray(0, 2).toString("utf-8")).toBe("PK")
    }
  }

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`/reports?projectId=${project.id}&runId=${run.id}`)
  await expect(
    page.getByRole("heading", { level: 1, name: "Evidence Center" }),
  ).toBeVisible()
  const hasHorizontalOverflow = await page.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  )
  expect(hasHorizontalOverflow).toBe(false)
})
