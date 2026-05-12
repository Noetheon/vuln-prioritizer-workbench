import { expect, type Page } from "@playwright/test"

const backendPort = process.env.VPW_PLAYWRIGHT_BACKEND_PORT ?? "18000"

export const backendBaseUrl = (
  process.env.VPW_E2E_BACKEND_URL ?? `http://127.0.0.1:${backendPort}`
).replace(/\/+$/, "")

export const testUserEmail =
  process.env.VPW_E2E_EMAIL ?? process.env.FIRST_SUPERUSER ?? "admin@example.com"

export async function login(page: Page): Promise<string> {
  await page.goto("/")
  await expect(page.getByRole("main")).toBeVisible()
  return ""
}

export function authHeaders(accessToken: string): Record<string, string> {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : {}
}
