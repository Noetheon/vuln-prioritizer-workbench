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
  if (viewport.width >= 1200) {
    expect(metrics.tableScrollWidth, JSON.stringify(metrics)).toBeLessThanOrEqual(
      metrics.regionClientWidth + 2,
    )
    expect(metrics.regionScrollWidth, JSON.stringify(metrics)).toBeLessThanOrEqual(
      metrics.regionClientWidth + 2,
    )
    expect(metrics.regionScrollLeft, JSON.stringify(metrics)).toBeLessThanOrEqual(
      1,
    )
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
  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.documentScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )

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

  await expect(page).toHaveURL(/\/reports(?:\?.*)?$/)
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

test("mobile status summary wraps without horizontal clipping", async ({
  page,
}) => {
  await login(page)
  await page.setViewportSize({ height: 844, width: 390 })
  await page.goto("/settings")

  const statusSummary = page.getByLabel("Workbench status summary")
  const headerHealth = page.getByLabel("Workspace health: Data services healthy")
  await expect(statusSummary).toBeVisible()
  const visibleHeaderHealthText = await headerHealth.evaluate((element) =>
    Array.from(element.querySelectorAll("span"))
      .filter((span) => getComputedStyle(span).display !== "none")
      .map((span) => span.textContent?.trim())
      .filter(Boolean)
      .join(" "),
  )
  expect(visibleHeaderHealthText).toBe("Healthy")

  const metrics = await statusSummary.evaluate((element) => {
    const rect = element.getBoundingClientRect()
    const children = Array.from(element.children[0]?.children ?? []).map(
      (child) => {
        const childRect = child.getBoundingClientRect()
        return {
          left: childRect.left,
          right: childRect.right,
        }
      },
    )

    return {
      display: getComputedStyle(element.children[0] as Element).display,
      fitsViewport: rect.left >= 0 && rect.right <= window.innerWidth,
      childrenFit: children.every(
        (child) => child.left >= 0 && child.right <= window.innerWidth,
      ),
    }
  })

  expect(metrics.display).toBe("grid")
  expect(metrics.fitsViewport).toBe(true)
  expect(metrics.childrenFit).toBe(true)
  await expectNoPageOverflow(page)
})

test("desktop shell keeps sidebar pinned while long content scrolls internally", async ({
  page,
}) => {
  await login(page)
  await page.setViewportSize({ height: 900, width: 1440 })
  await page.goto("/imports")
  await expect(page.getByRole("complementary", { name: "Workbench sidebar" }))
    .toBeVisible()
  await expect(
    page.getByRole("region", { name: "Workbench page content" }),
  ).toBeVisible()

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
