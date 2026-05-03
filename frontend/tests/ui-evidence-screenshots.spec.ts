import { mkdirSync } from "node:fs"
import path from "node:path"
import { expect, type Page, test } from "@playwright/test"

const screenshotDir = path.join(
  process.cwd(),
  "..",
  "docs",
  "ui-productization",
  "screenshots",
)

mkdirSync(screenshotDir, { recursive: true })

async function login(page: Page) {
  await page.goto("/login")
  await page.getByLabel("Email").fill("admin@example.com")
  await page.getByLabel("Password").fill("changethis")
  await page.getByRole("button", { name: "Sign in" }).click()
  await expect(page).toHaveURL(/\/$/)
}

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
    path: path.join(screenshotDir, fileName),
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
        page.getByRole("region", { name: "Import wizard" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-31-imports-dark-1440.png",
  )

  await captureRoute(
    page,
    "/reports",
    async () => {
      await expect(
        page.getByRole("region", { name: "Reports workspace" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-31-evidence-center-dark-1440.png",
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
        page.getByRole("region", { name: "Import wizard" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-imports-mobile-390.png",
  )

  await captureRoute(
    page,
    "/reports",
    async () => {
      await expect(
        page.getByRole("region", { name: "Reports workspace" }),
      ).toBeVisible({ timeout: 15_000 })
    },
    "ui-32-evidence-center-mobile-390.png",
  )
})
