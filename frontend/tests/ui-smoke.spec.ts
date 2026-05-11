import { expect, test } from "@playwright/test"
import { authHeaders, login } from "./auth-helpers"

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
    page.getByRole("heading", { name: "Validate and ingest source evidence" }),
  ).toBeVisible()
  await page.getByText("Advanced evidence controls").click()
  await expect(page.getByText("Provider and ATT&CK options")).toBeVisible()
  await expect(page.getByLabel("Provider snapshot file")).toBeVisible()
  await expect(page.getByLabel("ATT&CK source")).toBeVisible()
  await page.getByRole("combobox", { name: "Parser" }).click()
  await expect(page.getByRole("option", { name: "CycloneDX SBOM JSON" })).toBeVisible()
  await expect(page.getByRole("option", { name: "Nessus XML" })).toBeVisible()
  await page.keyboard.press("Escape")
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
  await expect(
    page.getByRole("region", { exact: true, name: "API tokens" }),
  ).toBeVisible()
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
      headers: authHeaders(accessToken),
    },
  )
  expect(response.status()).toBe(403)
})
