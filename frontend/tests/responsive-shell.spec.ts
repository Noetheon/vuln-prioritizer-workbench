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

test("mobile reports and settings keep content within the viewport", async ({
  page,
}) => {
  await login(page)

  for (const route of ["/reports", "/settings"]) {
    await page.goto(route)
    await expect(page.getByRole("main")).toBeVisible()
    await expectNoPageOverflow(page)
  }
})
