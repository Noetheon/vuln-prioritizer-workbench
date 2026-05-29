import { readFile } from "node:fs/promises"
import { expect, test } from "@playwright/test"
import {
  backendBaseUrl,
  localApiHeaders,
  openWorkbench,
} from "./workbench-runtime-helpers"

test("workbench demo workspace seeds persisted dashboard and reports", async ({
  page,
}) => {
  test.setTimeout(120_000)

  const demoStatusResponse = await page.request.get(
    `${backendBaseUrl}/api/v1/workbench/demo`,
    { headers: localApiHeaders() },
  )
  expect(demoStatusResponse.ok()).toBeTruthy()
  const demoStatus = (await demoStatusResponse.json()) as { enabled: boolean }
  expect(demoStatus.enabled).toBe(true)

  await openWorkbench(page)
  const demoAction = page
    .getByRole("button", {
      name: /Load demo(?: workspace)?|Reset demo(?: workspace)?/,
    })
    .first()
  await expect(demoAction).toBeVisible()
  await demoAction.click()

  await expect(
    page.getByText("Online Shop Demo Workspace").first(),
  ).toBeVisible({ timeout: 60_000 })
  await expect(page.getByText("Demo workspace").first()).toBeVisible()
  await expect(page.getByLabel("Critical Priority summary card")).toContainText(
    "24",
  )
  await expect(page.getByLabel("High EPSS summary card")).toContainText("24")
  await expect(
    page.getByRole("table", { name: "Findings by priority chart data" }),
  ).toContainText("Critical")
  await expect(
    page.getByRole("table", { name: "Findings by priority chart data" }),
  ).toContainText("24")
  await expect(
    page.getByRole("table", { name: "Findings by priority chart data" }),
  ).not.toContainText("Accepted")
  await page.getByRole("tab", { name: "EPSS Distribution" }).click()
  await expect(
    page.getByRole("table", { name: "EPSS distribution chart data" }),
  ).toContainText("Critical Exposure")
  await expect(
    page.getByRole("table", { name: "EPSS distribution chart data" }),
  ).toContainText("24")
  await expect(
    page.getByRole("link", { name: "CVE-2021-44228" }).first(),
  ).toBeVisible()
  await expect(
    page.getByRole("button", { name: /Reset demo(?: workspace)?/ }).first(),
  ).toBeVisible()

  await page
    .getByRole("navigation", { name: "Workbench navigation" })
    .getByRole("link", { name: "Assets" })
    .click()
  await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible()
  await expect(page.getByText("pay-api-01").first()).toBeVisible()
  await expect(page.getByText("edge-cache-02").first()).toBeVisible()

  await page
    .getByRole("navigation", { name: "Workbench navigation" })
    .getByRole("link", { name: "Risk Acceptance" })
    .click()
  await expect(
    page.getByRole("heading", { name: "Risk Acceptance" }),
  ).toBeVisible()
  const riskSummary = page.getByLabel("Risk acceptance summary")
  await expect(riskSummary).toContainText("Active decisions")
  await expect(riskSummary).toContainText("3")
  await expect(riskSummary).toContainText("Expiring soon")
  await expect(riskSummary).toContainText("1")
  await expect(page.getByText("DEMO-RISK-1001").first()).toBeVisible()
  await expect(page.getByText("DEMO-RISK-1004").first()).toBeVisible()

  await page
    .getByRole("navigation", { name: "Workbench navigation" })
    .getByRole("link", { name: "Evidence Center" })
    .click()
  await expect(
    page.getByRole("heading", { level: 1, name: "Evidence Center" }),
  ).toBeVisible()
  await page.getByRole("tab", { name: "History" }).click()
  const reportHistory = page.getByRole("table", { name: "Report history list" })
  await expect(reportHistory).toContainText("technical-report.md")
  await expect(reportHistory).toContainText("executive-report.html")
  await expect(reportHistory).toContainText("analysis-result.v2.json")
  await expect(reportHistory).toContainText("findings.csv")
  await expect(reportHistory).toContainText("attack-navigator-layer.json")
  await expect(reportHistory).toContainText("results.sarif")
  await expect(reportHistory).toContainText("evidence-bundle.zip")
})

test("workbench demo workspace downloads seeded report artifacts", async ({
  page,
}, testInfo) => {
  test.setTimeout(120_000)

  const demoStatusResponse = await page.request.get(
    `${backendBaseUrl}/api/v1/workbench/demo`,
    { headers: localApiHeaders() },
  )
  expect(demoStatusResponse.ok()).toBeTruthy()
  const demoStatus = (await demoStatusResponse.json()) as { enabled: boolean }
  expect(demoStatus.enabled).toBe(true)

  await openWorkbench(page)
  await page
    .getByRole("button", {
      name: /Load demo(?: workspace)?|Reset demo(?: workspace)?/,
    })
    .first()
    .click()
  await expect(
    page.getByText("Online Shop Demo Workspace").first(),
  ).toBeVisible({ timeout: 60_000 })

  await page
    .getByRole("navigation", { name: "Workbench navigation" })
    .getByRole("link", { name: "Evidence Center" })
    .click()
  await expect(
    page.getByRole("heading", { level: 1, name: "Evidence Center" }),
  ).toBeVisible()
  await page.getByRole("tab", { name: "History" }).click()

  for (const artifact of demoReportArtifacts) {
    const downloadPromise = page.waitForEvent("download")
    await page
      .getByRole("button", { name: `Download ${artifact.filename}` })
      .click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toBe(artifact.filename)
    expect(await download.failure()).toBeNull()

    const targetPath = testInfo.outputPath(artifact.filename)
    await download.saveAs(targetPath)
    const bytes = await readFile(targetPath)
    expect(bytes.byteLength).toBeGreaterThan(artifact.minimumBytes)
    artifact.assertContent(bytes)
  }
})

const demoReportArtifacts = [
  {
    filename: "technical-report.md",
    minimumBytes: 1_000,
    assertContent(bytes: Buffer) {
      expect(bytes.toString("utf-8")).toContain(
        "# Technical Vulnerability Report",
      )
    },
  },
  {
    filename: "executive-report.html",
    minimumBytes: 1_000,
    assertContent(bytes: Buffer) {
      const content = bytes.toString("utf-8")
      expect(content).toContain("<!doctype html>")
      expect(content).toContain("Decision Brief")
      expect(content).not.toContain("Executive Summary")
    },
  },
  {
    filename: "analysis-result.v2.json",
    minimumBytes: 1_000,
    assertContent(bytes: Buffer) {
      const payload = JSON.parse(bytes.toString("utf-8")) as { schema: string }
      expect(payload.schema).toBe("analysis-result.v2")
    },
  },
  {
    filename: "findings.csv",
    minimumBytes: 500,
    assertContent(bytes: Buffer) {
      const content = bytes.toString("utf-8")
      expect(content).toContain("cve_id")
      expect(content).toContain("CVE-")
    },
  },
  {
    filename: "attack-navigator-layer.json",
    minimumBytes: 500,
    assertContent(bytes: Buffer) {
      const payload = JSON.parse(bytes.toString("utf-8")) as {
        domain: string
        techniques: Array<{ techniqueID: string }>
        version: string
      }
      expect(payload.version).toBe("4.5")
      expect(payload.domain).toBe("enterprise-attack")
      expect(payload.techniques.length).toBeGreaterThan(0)
    },
  },
  {
    filename: "results.sarif",
    minimumBytes: 1_000,
    assertContent(bytes: Buffer) {
      const payload = JSON.parse(bytes.toString("utf-8")) as {
        version: string
      }
      expect(payload.version).toBe("2.1.0")
    },
  },
  {
    filename: "evidence-bundle.zip",
    minimumBytes: 1_000,
    assertContent(bytes: Buffer) {
      expect(bytes.subarray(0, 2).toString("utf-8")).toBe("PK")
    },
  },
]
