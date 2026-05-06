import { expect, type Page, test } from "@playwright/test"
import { login } from "./auth-helpers"
import { evidenceScreenshotPath } from "./evidence-paths"

async function captureRoute(
  page: Page,
  route: string,
  selectorAssertion: () => Promise<void>,
  fileName: string,
) {
  await page.goto(route)
  await selectorAssertion()
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("ui-productization", "screenshots", fileName),
  })
}

test("evidence: ui-31 dark-mode screenshots", async ({ page }) => {
  test.setTimeout(120_000)
  await page.emulateMedia({ colorScheme: "dark" })
  await page.setViewportSize({ height: 1100, width: 1440 })
  await login(page)

  await captureRoute(
    page,
    "/",
    async () => {
      await expect(
        page
          .getByRole("heading", { name: "Risk Operations", level: 1 })
          .first(),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-31-dashboard-dark-1440.png",
  )

  await captureRoute(
    page,
    "/findings",
    async () => {
      await expect(
        page.getByRole("region", { name: "Findings filters" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-31-findings-dark-1440.png",
  )

  await captureRoute(
    page,
    "/imports",
    async () => {
      await expect(
        page.getByRole("heading", { name: "Import Wizard" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-31-imports-dark-1440.png",
  )

  await captureRoute(
    page,
    "/reports",
    async () => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Evidence Center" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-31-evidence-center-dark-1440.png",
  )

  await captureRoute(
    page,
    "/assets",
    async () => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Assets" }),
      ).toBeVisible({ timeout: 15_000 })
      await expect(
        page.getByRole("heading", { level: 2, name: "Assets" }).first(),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-31-assets-dark-1440.png",
  )
})

test("evidence: ui-32 responsive screenshots (tablet/mobile)", async ({
  page,
}) => {
  test.setTimeout(120_000)
  await page.setViewportSize({ height: 844, width: 390 })
  await login(page)

  await captureRoute(
    page,
    "/",
    async () => {
      await expect(
        page
          .getByRole("heading", { name: "Risk Operations", level: 1 })
          .first(),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-dashboard-mobile-390.png",
  )

  await captureRoute(
    page,
    "/findings",
    async () => {
      await expect(
        page.getByRole("region", { name: "Findings filters" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-findings-mobile-390.png",
  )

  await captureRoute(
    page,
    "/imports",
    async () => {
      await expect(
        page.getByRole("heading", { name: "Import Wizard" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-imports-mobile-390.png",
  )

  await captureRoute(
    page,
    "/reports",
    async () => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Evidence Center" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-evidence-center-mobile-390.png",
  )

  await page.setViewportSize({ height: 900, width: 1440 })
  await captureRoute(
    page,
    "/assets",
    async () => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Assets" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-assets-desktop-1440.png",
  )

  await page.setViewportSize({ height: 1024, width: 768 })
  await captureRoute(
    page,
    "/assets",
    async () => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Assets" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-assets-tablet-768.png",
  )

  await page.setViewportSize({ height: 844, width: 390 })
  await captureRoute(
    page,
    "/assets",
    async () => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Assets" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-assets-mobile-390.png",
  )
})
