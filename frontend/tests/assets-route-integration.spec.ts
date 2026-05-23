import { expect, test } from "@playwright/test"

import { selectRadixOptionByLabel, validAssetContextCsv } from "./workbench-e2e-helpers"
import {
  mockAsset,
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

test("assets route uses inventory table with drawer modes", async ({ page }) => {
  await routeWorkbenchShell(page, {
    assets: [mockAsset],
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto("/assets")
  await expect(
    page.getByRole("heading", { level: 2, name: "Asset context" }),
  ).toBeVisible()
  const assetsTable = page.getByRole("table", { name: "Assets table" })
  await expect(assetsTable).toContainText("build-host-1")
  await expect(
    assetsTable.getByRole("button", {
      name: "Select asset build-host-1, target host:build-host-1",
    }),
  ).toBeVisible()
  await expect(
    assetsTable.getByRole("button", {
      exact: true,
      name: "build-host-1build-host-1",
    }),
  ).toHaveCount(0)
  await expect(
    page.getByRole("form", { name: "Create Asset form fields" }),
  ).toHaveCount(0)
  await expect(
    page.getByRole("form", { name: "Import Asset Context form fields" }),
  ).toHaveCount(0)

  await page.getByRole("button", { name: "Add asset" }).click()
  const createDrawer = page.getByRole("dialog", { name: "Add asset" })
  await expect(createDrawer).toBeVisible()
  await createDrawer.getByRole("button", { name: "Create Asset" }).click()
  await expect(page.getByText("Asset key is required.")).toBeVisible()
  await createDrawer.getByLabel("Asset key").fill("api-host-1")
  await createDrawer.getByLabel("Asset name").fill("api-host-1")
  await createDrawer.getByLabel("Owner").fill("team-api")
  await createDrawer.getByLabel("Business service").fill("api")
  await createDrawer.getByLabel("Target ref").fill("host:api-host-1")
  await selectRadixOptionByLabel(page, createDrawer, "Criticality", "High")
  await selectRadixOptionByLabel(page, createDrawer, "Environment", "Staging")
  await selectRadixOptionByLabel(page, createDrawer, "Exposure", "Internal")
  await createDrawer.getByRole("button", { name: "Create Asset" }).click()
  await expect(page.getByText("Asset api-host-1 created.")).toBeVisible()
  await page.getByRole("button", { name: "Close" }).click()
  await expect(assetsTable).toContainText("api-host-1")

  const buildHostRow = assetsTable.locator("tbody tr").filter({
    hasText: "build-host-1",
  })
  await buildHostRow.getByRole("button", { name: "View" }).click()
  const detailDrawer = page.getByRole("dialog", { name: "build-host-1" })
  await expect(detailDrawer).toContainText("Asset detail")
  await expect(detailDrawer).toContainText("Internet Facing")
  await detailDrawer.getByRole("button", { name: "Findings" }).click()
  const findingsDrawer = page.getByRole("dialog", {
    name: /Linked findings for build-host-1/,
  })
  await expect(
    findingsDrawer.getByRole("table", { name: "Asset findings table" }),
  ).toContainText("CVE-2024-3094")
  await expect(
    findingsDrawer.getByRole("link", { name: "Open findings" }),
  ).toHaveAttribute("href", /\/findings\?.*assetId=asset-1/)
  await page.getByRole("button", { name: "Close" }).click()

  await buildHostRow.getByRole("button", { name: "Edit" }).click()
  const editDrawer = page.getByRole("dialog", { name: "Edit build-host-1" })
  await expect(editDrawer).toBeVisible()
  await editDrawer.getByLabel("Edit owner").fill("team-platform-updated")
  await editDrawer.getByRole("button", { name: "Save Asset" }).click()
  await expect(page.getByText("Asset build-host-1 updated.")).toBeVisible()
  await page.getByRole("button", { name: "Close" }).click()
  await expect(assetsTable).toContainText("team-platform-updated")

  await page.getByRole("button", { name: "Import assets" }).click()
  const importDrawer = page.getByRole("dialog", { name: "Import assets" })
  await importDrawer.getByLabel("Asset context CSV").setInputFiles({
    buffer: validAssetContextCsv,
    mimeType: "text/csv",
    name: "assets.csv",
  })
  await importDrawer.getByRole("button", { name: "Upload context" }).click()
  await expect(
    page.getByText("Imported 1 asset(s); 0 finding(s) need recalculation."),
  ).toBeVisible()
  await expect(assetsTable).toContainText("imported-host-1")

  await buildHostRow.getByRole("button", { name: "Recalculate" }).click()
  await expect(
    page.getByText("Recalculated 1 finding(s) for build-host-1."),
  ).toBeVisible()
  await expect(buildHostRow).toContainText("Current")
})

test("assets drawer remains usable on mobile", async ({ page }) => {
  await routeWorkbenchShell(page, {
    assets: [mockAsset],
    findings: [mockFinding],
    projects: [mockProject],
  })
  await page.setViewportSize({ height: 844, width: 390 })
  await page.goto("/assets")

  await expect(
    page.getByRole("table", { name: "Assets table" }),
  ).toBeHidden()
  const assetsCards = page.getByRole("region", { name: "Assets table cards" })
  await expect(assetsCards).toBeVisible()
  await assetsCards
    .getByRole("article")
    .filter({ hasText: "build-host-1" })
    .getByRole("button", { name: "View" })
    .click()

  await expect(
    page.getByRole("dialog", { name: "build-host-1" }),
  ).toBeVisible()
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  )
  expect(overflow).toBeLessThanOrEqual(1)
})
