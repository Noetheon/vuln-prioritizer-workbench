import { expect, type Page, test } from "@playwright/test"
import { openWorkbench } from "./workbench-runtime-helpers"
import { evidenceScreenshotPath } from "./evidence-paths"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

async function expectNoPageOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    bodyScrollWidth: document.body.scrollWidth,
    viewportWidth: document.documentElement.clientWidth,
  }))

  expect(dimensions.bodyScrollWidth).toBeLessThanOrEqual(
    dimensions.viewportWidth + 1,
  )
}

async function expectNoGlobalStatusStrip(page: Page) {
  await expect(page.getByLabel("Workbench status summary")).toHaveCount(0)
}

async function expectWqhdContainerBehavior(
  page: Page,
  viewport: { width: number; height: number },
) {
  const metrics = await page
    .locator(
      'section[aria-label="Workbench page content"] > .vpw-page-container',
    )
    .first()
    .evaluate((container) => {
      const rect = container.getBoundingClientRect()
      return {
        cssMaxWidth: getComputedStyle(container).maxWidth,
        width: rect.width,
      }
    })

  expect(metrics.cssMaxWidth).toBe("2400px")
  expect(metrics.width).toBeLessThanOrEqual(2402)
  if (viewport.width >= 2560) {
    expect(metrics.width).toBeGreaterThanOrEqual(2300)
  }
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

  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(metrics.viewportWidth + 1)
  expect(metrics.documentScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(["auto", "scroll"]).toContain(metrics.overflowX)
  expect(metrics.regionClientWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  if (viewport.width >= 1200) {
    expect(
      metrics.tableScrollWidth,
      JSON.stringify(metrics),
    ).toBeLessThanOrEqual(metrics.regionClientWidth + 2)
    expect(
      metrics.regionScrollWidth,
      JSON.stringify(metrics),
    ).toBeLessThanOrEqual(metrics.regionClientWidth + 2)
    expect(
      metrics.regionScrollLeft,
      JSON.stringify(metrics),
    ).toBeLessThanOrEqual(1)
  } else {
    expect(metrics.tableScrollWidth, JSON.stringify(metrics)).toBeGreaterThan(
      metrics.regionClientWidth,
    )
    expect(metrics.regionScrollWidth, JSON.stringify(metrics)).toBeGreaterThan(
      metrics.regionClientWidth,
    )
    expect(metrics.regionScrollLeft, JSON.stringify(metrics)).toBeGreaterThan(0)
  }

  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath(
      "ui-productization",
      "screenshots",
      `vpw-aud-201-findings-${viewport.width}.png`,
    ),
  })
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath(
      "ui-productization",
      "screenshots",
      `vpw-aud-204-findings-table-scroll-${viewport.width}.png`,
    ),
  })
}

async function expectFindingsMobileCards(page: Page) {
  const cardsRegion = page.getByRole("region", {
    name: "Findings remediation cards",
  })
  await expect(cardsRegion).toBeVisible()
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toBeHidden()

  const metrics = await page
    .locator('[data-testid="findings-mobile-cards"]')
    .evaluate((region) => {
      const cards = Array.from(
        region.querySelectorAll('[data-testid="findings-mobile-card"]'),
      )
      const documentElement = document.documentElement
      return {
        bodyScrollWidth: document.body.scrollWidth,
        cardCount: cards.length,
        cardsFit: cards.every((card) => {
          const rect = card.getBoundingClientRect()
          return rect.left >= 0 && rect.right <= documentElement.clientWidth
        }),
        documentScrollWidth: documentElement.scrollWidth,
        viewportWidth: documentElement.clientWidth,
      }
    })

  expect(metrics.cardCount).toBeGreaterThan(0)
  expect(metrics.cardsFit).toBe(true)
  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(metrics.viewportWidth + 1)
  expect(metrics.documentScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )

  const card = page.getByRole("article", {
    name: `Finding ${mockFinding.cve_id}`,
  })
  await expect(card).toContainText("xz")
  await expect(card).toContainText("payments / build-host-1")
  await expect(card).toContainText("Owner")
  await expect(card).toContainText("platform")
  await expect(card).toContainText("Status")
  await expect(card).toContainText("Known exploited dependency")

  await page
    .getByRole("button", { name: `Quick view ${mockFinding.cve_id}` })
    .click()
  const drawer = page.getByRole("dialog", {
    name: new RegExp(mockFinding.cve_id),
  })
  await expect(drawer).toBeVisible()
  await expect
    .poll(async () =>
      drawer.evaluate((element) => {
        const rect = element.getBoundingClientRect()
        const viewportWidth = document.documentElement.clientWidth
        return rect.left >= 0 && rect.right <= viewportWidth
      }),
    )
    .toBe(true)
  const drawerMetrics = await drawer.evaluate((element) => {
    const rect = element.getBoundingClientRect()
    return {
      bodyScrollWidth: document.body.scrollWidth,
      height: rect.height,
      left: rect.left,
      right: rect.right,
      viewportHeight: window.innerHeight,
      viewportWidth: document.documentElement.clientWidth,
    }
  })
  expect(drawerMetrics.left).toBeGreaterThanOrEqual(0)
  expect(drawerMetrics.right).toBeLessThanOrEqual(drawerMetrics.viewportWidth)
  expect(drawerMetrics.height).toBeLessThanOrEqual(drawerMetrics.viewportHeight)
  expect(drawerMetrics.bodyScrollWidth).toBeLessThanOrEqual(
    drawerMetrics.viewportWidth + 1,
  )
  await expect(
    drawer.getByRole("button", { name: "Close" }).first(),
  ).toBeInViewport()
  await expect(
    drawer.getByRole("link", { name: "Open full detail" }),
  ).toBeInViewport()
  await expect(drawer).toContainText("Decision summary")
  await expect(drawer).toContainText("Open full detail")
  await expect(
    drawer.getByRole("link", { name: "Open full detail" }),
  ).toHaveAttribute("href", /\/findings\/finding-1/)
  await drawer.getByRole("button", { name: "Close" }).first().click()
  await expect(drawer).toHaveCount(0)

  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath(
      "ui-productization",
      "screenshots",
      "vpw-aud-201-findings-390.png",
    ),
  })
  await cardsRegion.screenshot({
    path: evidenceScreenshotPath(
      "ui-productization",
      "screenshots",
      "vpw-aud-204-findings-mobile-cards-390.png",
    ),
  })
}

const workbenchRoutes = [
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

const responsiveViewports = [
  { height: 800, width: 360 },
  { height: 667, width: 375 },
  { height: 844, width: 390 },
  { height: 1024, width: 768 },
  { height: 900, width: 1440 },
  { height: 1080, width: 1920 },
  { height: 1440, width: 2560 },
] as const

test("mobile shell exposes drawer navigation without page-width overflow", async ({
  page,
}) => {
  await page.setViewportSize({ height: 844, width: 390 })
  await openWorkbench(page)
  await expectNoPageOverflow(page)

  const navButton = page.getByRole("button", { name: "Open navigation" })
  await navButton.click()
  const navDialog = page.getByRole("dialog", { name: "Vuln Prioritizer" })
  await expect(navDialog).toBeVisible()
  await expect(navDialog.locator(":focus")).toBeVisible()
  await expect(
    navDialog.getByRole("navigation", { name: "Workbench mobile navigation" }),
  ).toBeVisible()
  await expect(navDialog.getByRole("button", { name: "Close" })).toBeVisible()
  await expect
    .poll(async () =>
      navDialog.evaluate((element) => {
        const rect = element.getBoundingClientRect()
        const viewportWidth = document.documentElement.clientWidth
        return rect.left >= 0 && rect.right <= viewportWidth
      }),
    )
    .toBe(true)
  const navMetrics = await navDialog.evaluate((element) => {
    const rect = element.getBoundingClientRect()
    return {
      left: rect.left,
      right: rect.right,
      viewportWidth: document.documentElement.clientWidth,
    }
  })
  expect(navMetrics.left).toBeGreaterThanOrEqual(0)
  expect(navMetrics.right).toBeLessThanOrEqual(navMetrics.viewportWidth)

  await page.keyboard.press("Escape")
  await expect(navDialog).toHaveCount(0)
  await expect(navButton).toBeFocused()

  await navButton.click()
  await expect(navDialog).toBeVisible()
  await navDialog.getByRole("link", { name: "Evidence Center" }).click()

  await expect(page).toHaveURL(/\/reports(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { name: "Generate Evidence Artifacts" }),
  ).toBeVisible()
  for (const tabName of [
    "Artifacts",
    "Decision Summary",
    "Manifest & Verification",
    "History",
    "Data Quality",
  ]) {
    await page.getByRole("tab", { name: tabName }).click()
    await expect(page.getByRole("tab", { name: tabName })).toHaveAttribute(
      "aria-selected",
      "true",
    )
    await expectNoPageOverflow(page)
  }
  await expectNoPageOverflow(page)
})

test("Workbench routes keep content within desktop, tablet, and mobile viewports", async ({
  page,
}) => {
  test.setTimeout(180_000)
  await openWorkbench(page)

  for (const viewport of responsiveViewports) {
    await page.setViewportSize(viewport)
    for (const route of workbenchRoutes) {
      await page.goto(route)
      await expect(page.getByRole("main")).toBeVisible()
      await page.keyboard.press("Tab")
      await expect(page.locator(":focus")).toBeVisible()
      await expectNoPageOverflow(page)
      await expectNoGlobalStatusStrip(page)
      await expectWqhdContainerBehavior(page, viewport)
    }
  }
})

test("mobile shell keeps compact health status without duplicate summary strip", async ({
  page,
}) => {
  await routeWorkbenchShell(page, { projects: [mockProject] })
  await page.setViewportSize({ height: 844, width: 390 })
  await page.goto("/settings")

  const statusSummary = page.getByLabel("Workbench status summary")
  const headerHealth = page.getByLabel(
    "Workspace health: Data services healthy",
  )
  await expect(statusSummary).toHaveCount(0)
  const visibleHeaderHealthText = await headerHealth.evaluate((element) =>
    Array.from(element.querySelectorAll("span"))
      .filter((span) => getComputedStyle(span).display !== "none")
      .map((span) => span.textContent?.trim())
      .filter(Boolean)
      .join(" "),
  )
  expect(visibleHeaderHealthText).toBe("Healthy")
  await expectNoPageOverflow(page)
})

test("desktop shell keeps sidebar pinned while long content scrolls internally", async ({
  page,
}) => {
  await openWorkbench(page)
  await page.setViewportSize({ height: 900, width: 1440 })
  await page.goto("/imports")
  await expect(
    page.getByRole("complementary", { name: "Workbench sidebar" }),
  ).toBeVisible()
  await expect(
    page.getByRole("region", { name: "Workbench page content" }),
  ).toBeVisible()
  await page.evaluate(() => {
    const content = document.querySelector<HTMLElement>(
      'section[aria-label="Workbench page content"]',
    )
    const spacer = document.createElement("div")
    spacer.setAttribute("aria-hidden", "true")
    spacer.style.minHeight = "1200px"
    content?.appendChild(spacer)
  })

  const metrics = await page.evaluate(() => {
    const sidebar = document.querySelector(
      'aside[aria-label="Workbench sidebar"]',
    )
    const content = document.querySelector<HTMLElement>(
      'section[aria-label="Workbench page content"]',
    )
    content?.scrollTo({ top: content.scrollHeight })
    const sidebarRect = sidebar?.getBoundingClientRect()
    const bottomLeftElement = document.elementFromPoint(24, innerHeight - 24)

    return {
      bodyOverflowY: getComputedStyle(document.body).overflowY,
      contentClientHeight: content?.clientHeight ?? 0,
      contentOverflowY: content ? getComputedStyle(content).overflowY : "",
      contentScrollHeight: content?.scrollHeight ?? 0,
      contentScrollTop: content?.scrollTop ?? 0,
      pageScrollY: scrollY,
      sidebarBottom: sidebarRect?.bottom ?? 0,
      sidebarHeight: sidebarRect?.height ?? 0,
      sidebarIsAtBottom:
        bottomLeftElement?.closest('aside[aria-label="Workbench sidebar"]') !==
        null,
      sidebarTop: sidebarRect?.top ?? 0,
      viewportHeight: innerHeight,
    }
  })

  expect(metrics.bodyOverflowY).toBe("hidden")
  expect(metrics.contentOverflowY).toBe("auto")
  expect(metrics.contentScrollHeight).toBeGreaterThan(
    metrics.contentClientHeight,
  )
  expect(metrics.contentScrollTop).toBeGreaterThan(0)
  expect(metrics.pageScrollY).toBe(0)
  expect(metrics.sidebarTop).toBe(0)
  expect(Math.round(metrics.sidebarHeight)).toBe(metrics.viewportHeight)
  expect(Math.round(metrics.sidebarBottom)).toBe(metrics.viewportHeight)
  expect(metrics.sidebarIsAtBottom).toBe(true)
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
  ]) {
    await page.setViewportSize(viewport)
    await page.goto("/findings")
    await expect(page.getByRole("main")).toBeVisible()
    await expectFindingsTableScrollContainment(page, viewport)
  }

  await page.setViewportSize({ height: 844, width: 390 })
  await page.goto("/findings")
  await expect(page.getByRole("main")).toBeVisible()
  await expectFindingsMobileCards(page)
})
