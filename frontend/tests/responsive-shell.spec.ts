import { expect, type Page, test } from "@playwright/test"
import { login } from "./auth-helpers"

async function expectNoPageOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    bodyScrollWidth: document.body.scrollWidth,
    viewportWidth: document.documentElement.clientWidth,
  }))

  expect(dimensions.bodyScrollWidth).toBeLessThanOrEqual(
    dimensions.viewportWidth + 1,
  )
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
