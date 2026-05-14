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
    .getByRole("link", { name: "Waivers" })
    .click()
  await expect(page.getByRole("heading", { name: "Waivers" })).toBeVisible()
  await expect(page.getByText("Active: 3", { exact: true })).toBeVisible()
  await expect(
    page.getByText("Expiring soon: 1", { exact: true }),
  ).toBeVisible()
  await expect(page.getByText("DEMO-RISK-1001").first()).toBeVisible()
  await expect(page.getByText("DEMO-RISK-1004").first()).toBeVisible()

  await page
    .getByRole("navigation", { name: "Workbench navigation" })
    .getByRole("link", { name: "Reports" })
    .click()
  await expect(
    page.getByRole("heading", { level: 1, name: "Evidence Center" }),
  ).toBeVisible()
  const reportHistory = page.getByRole("table", { name: "Report history list" })
  await expect(reportHistory).toContainText("technical-report.md")
  await expect(reportHistory).toContainText("executive-report.html")
  await expect(reportHistory).toContainText("analysis-result.v1.json")
  await expect(reportHistory).toContainText("findings.csv")
  await expect(reportHistory).toContainText("attack-navigator-layer.json")
  await expect(reportHistory).toContainText("results.sarif")
  await expect(reportHistory).toContainText("evidence-bundle.zip")
})
