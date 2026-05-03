import { expect, type Page, test } from "@playwright/test"

async function login(page: Page) {
  await page.goto("/login")
  await page.getByLabel("Email").fill("admin@example.com")
  await page.getByLabel("Password").fill("changethis")
  await page.getByRole("button", { name: "Sign in" }).click()
  await expect(page).toHaveURL(/\/$/)
}

test("smoke: dashboard renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/")
  await expect(
    page.getByRole("heading", { name: "Risk Operations", level: 1 }).first(),
  ).toBeVisible()
})

test("smoke: imports renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/imports")
  await expect(
    page.getByRole("heading", { name: "Import Wizard" }),
  ).toBeVisible()
})

test("smoke: findings renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/findings")
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()
})

test("smoke: evidence center renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/reports")
  await expect(
    page.getByRole("heading", { name: "Generate Evidence Artifacts" }),
  ).toBeVisible()
})

test("smoke: providers renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/providers")
  await expect(
    page.getByRole("heading", { name: "Provider sources" }),
  ).toBeVisible()
})

test("smoke: settings renders", async ({ page }) => {
  test.setTimeout(30_000)
  await login(page)
  await page.goto("/settings")
  await expect(page.getByRole("region", { name: "API tokens" })).toBeVisible()
})
