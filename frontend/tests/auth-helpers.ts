import { expect, type Page } from "@playwright/test"

export const testUserEmail =
  process.env.VPW_E2E_EMAIL ?? process.env.FIRST_SUPERUSER ?? "admin@example.com"
export const testUserPassword =
  process.env.VPW_E2E_PASSWORD ??
  process.env.FIRST_SUPERUSER_PASSWORD ??
  "local-workbench-dev-password"

export async function login(page: Page): Promise<string> {
  const responsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/api/v1/login/access-token") &&
      response.request().method() === "POST",
  )

  await page.goto("/login")
  await expect(page.getByLabel("Email")).toHaveValue("")
  await expect(page.getByLabel("Password")).toHaveValue("")
  await page.getByLabel("Email").fill(testUserEmail)
  await page.getByLabel("Password").fill(testUserPassword)
  await page.getByRole("button", { name: "Sign in" }).click()

  const response = await responsePromise
  expect(response.ok(), await response.text()).toBeTruthy()
  const body = (await response.json().catch(() => ({}))) as {
    access_token?: unknown
  }
  await expect(page).toHaveURL(/\/(?:\?.*)?$/)
  return typeof body.access_token === "string" ? body.access_token : ""
}

export function authHeaders(accessToken: string): Record<string, string> {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : {}
}
