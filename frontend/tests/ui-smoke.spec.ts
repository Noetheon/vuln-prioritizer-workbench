import { expect, type Page, test } from "@playwright/test"

async function login(page: Page): Promise<string> {
  await page.goto("/login")
  await page.getByLabel("Email").fill("admin@example.com")
  await page.getByLabel("Password").fill("changethis")
  await page.getByRole("button", { name: "Sign in" }).click()
  await expect(page).toHaveURL(/\/$/)
  const accessToken = await page.evaluate(() =>
    window.localStorage.getItem("access_token"),
  )
  expect(accessToken).toBeTruthy()
  return accessToken ?? ""
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

test("smoke: sign out revokes the active session", async ({ page }) => {
  test.setTimeout(30_000)
  const accessToken = await login(page)

  await page.getByRole("button", { name: "Account menu" }).click()
  await page.getByRole("menuitem", { name: "Sign out" }).click()

  await expect(page).toHaveURL(/\/login$/)
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
  const response = await page.request.get(
    "http://127.0.0.1:8000/api/v1/users/me",
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  )
  expect(response.status()).toBe(403)
})
