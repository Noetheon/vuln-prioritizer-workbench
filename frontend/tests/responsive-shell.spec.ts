import { expect, type Page, test } from "@playwright/test"
import { login } from "./auth-helpers"
import { evidenceScreenshotPath } from "./evidence-paths"
import { mockFinding, mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

async function expectNoPageOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    bodyScrollWidth: document.body.scrollWidth,
    viewportWidth: document.documentElement.clientWidth,
  }))

  expect(dimensions.bodyScrollWidth).toBeLessThanOrEqual(
    dimensions.viewportWidth + 1,
  )
}

async function expectFindingsTableScrollContainment(
  page: Page,
  viewport: { width: number; height: number },
) {
  const scrollRegion = page.getByRole("region", {
    name: "Findings table scroll region",
  })
  await expect(scrollRegion).toBeVisible()
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toBeVisible()

  const metrics = await scrollRegion.evaluate((region) => {
    const table = region.querySelector("table")
    const documentElement = document.documentElement
    const style = window.getComputedStyle(region)
    const tableStyle = table ? window.getComputedStyle(table) : null
    region.scrollLeft = region.scrollWidth
    return {
      bodyScrollWidth: document.body.scrollWidth,
      computedTableMinWidth: tableStyle?.minWidth ?? "",
      computedTableWidth: tableStyle?.width ?? "",
      documentScrollWidth: documentElement.scrollWidth,
      overflowX: style.overflowX,
      regionClientWidth: region.clientWidth,
      regionScrollLeft: region.scrollLeft,
      regionScrollWidth: region.scrollWidth,
      tableScrollWidth: table?.scrollWidth ?? 0,
      viewportWidth: documentElement.clientWidth,
    }
  })

  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.documentScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(["auto", "scroll"]).toContain(metrics.overflowX)
  expect(metrics.regionClientWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.tableScrollWidth, JSON.stringify(metrics)).toBeGreaterThan(
    metrics.regionClientWidth,
  )
  expect(metrics.regionScrollWidth, JSON.stringify(metrics)).toBeGreaterThan(
    metrics.regionClientWidth,
  )
  expect(metrics.regionScrollLeft, JSON.stringify(metrics)).toBeGreaterThan(0)

  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath(
      "ui-productization",
      "screenshots",
      `vpw-aud-201-findings-${viewport.width}.png`,
    ),
  })
}

const authenticatedRoutes = [
  "/",
  "/projects",
  "/imports",
  "/findings",
  "/assets",
  "/waivers",
  "/reports",
  "/providers",
  "/settings",
] as const

test("mobile shell exposes drawer navigation without page-width overflow", async ({
  page,
}) => {
  await login(page)
  await expectNoPageOverflow(page)

  await page.getByRole("button", { name: "Open navigation" }).click()
  await expect(
    page.getByRole("navigation", { name: "Workbench mobile navigation" }),
  ).toBeVisible()
  await page.getByRole("link", { name: "Reports" }).click()

  await expect(page).toHaveURL(/\/reports$/)
  await expect(
    page.getByRole("heading", { name: "Generate Evidence Artifacts" }),
  ).toBeVisible()
  await expectNoPageOverflow(page)
})

test("authenticated routes keep content within desktop, tablet, and mobile viewports", async ({
  page,
}) => {
  test.setTimeout(120_000)
  await login(page)

  for (const viewport of [
    { height: 900, width: 1440 },
    { height: 1024, width: 768 },
    { height: 844, width: 390 },
  ]) {
    await page.setViewportSize(viewport)
    for (const route of authenticatedRoutes) {
      await page.goto(route)
      await expect(page.getByRole("main")).toBeVisible()
      await page.keyboard.press("Tab")
      await expect(page.locator(":focus")).toBeVisible()
      await expectNoPageOverflow(page)
    }
  }
})

test("findings table keeps horizontal scroll contained at desktop, tablet, and mobile widths", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })

  for (const viewport of [
    { height: 900, width: 1440 },
    { height: 1024, width: 768 },
    { height: 844, width: 390 },
  ]) {
    await page.setViewportSize(viewport)
    await page.goto("/findings")
    await expect(page.getByRole("main")).toBeVisible()
    await expectFindingsTableScrollContainment(page, viewport)
  }
})
