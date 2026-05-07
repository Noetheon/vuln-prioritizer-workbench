import { expect, test } from "@playwright/test"
import { mockFinding, mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

test("findings route renders the empty live queue without demo data", async ({
  page,
}) => {
  await routeWorkbenchShell(page)
  await page.goto("/findings")

  await expect(page.getByText("Demo preview")).toHaveCount(0)
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()

  await expect(page.getByText("Finding Decisions")).toHaveCount(0)
  await expect(page.getByText("Provider Status")).toHaveCount(0)
  await expect(page.getByText("Evidence Flow")).toHaveCount(0)

  await expect(page.getByText("No projects yet")).toBeVisible()
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toHaveCount(0)

  await expect(
    page.getByRole("combobox", { name: "Sort direction" }),
  ).toHaveCount(0)

  const sidebar = page.getByLabel("Workbench sidebar")
  await expect(sidebar).toHaveCSS("width", "248px")
  await expect(page.getByText("Sign out")).toHaveCount(0)
  await page.getByRole("button", { name: "Account menu" }).click()
  await expect(page.getByRole("menuitem", { name: "Sign out" })).toBeVisible()
  await page.keyboard.press("Escape")
  await page.getByRole("button", { name: "Collapse sidebar" }).click()
  await expect(sidebar).toHaveCSS("width", "72px")
  await expect(
    page.getByRole("button", { name: "Expand sidebar" }),
  ).toBeVisible()
  await expect(
    page
      .getByRole("navigation", { name: "Workbench navigation" })
      .getByText("Dashboard"),
  ).toHaveCount(0)
})

test("finding detail API errors do not fall back to demo findings", async ({
  page,
}) => {
  await routeWorkbenchShell(page)
  await page.route("**/api/v1/findings/demo-f1", (route) =>
    route.fulfill({
      contentType: "application/json",
      status: 404,
      body: JSON.stringify({ detail: "Finding not found" }),
    }),
  )

  await page.goto("/findings/demo-f1")

  await expect(page.getByText("Finding detail unavailable")).toBeVisible()
  await expect(page.getByText("Demo preview")).toHaveCount(0)
  await expect(page.getByText("CVE-2024-3094")).toHaveCount(0)
})

test("findings table owns horizontal scroll without page overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 768, height: 1024 })
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto("/findings")

  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toContainText("CVE-2024-3094")
  const scrollRegion = page.getByRole("region", {
    name: "Findings table scroll region",
  })
  const metrics = await scrollRegion.evaluate((region) => {
    const documentElement = document.documentElement
    region.scrollLeft = region.scrollWidth
    return {
      bodyScrollWidth: document.body.scrollWidth,
      documentScrollWidth: documentElement.scrollWidth,
      regionClientWidth: region.clientWidth,
      regionScrollLeft: region.scrollLeft,
      regionScrollWidth: region.scrollWidth,
      viewportWidth: documentElement.clientWidth,
    }
  })

  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.documentScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.regionClientWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.regionScrollWidth).toBeGreaterThan(metrics.regionClientWidth)
  expect(metrics.regionScrollLeft).toBeGreaterThan(0)
})
