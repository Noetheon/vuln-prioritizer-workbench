import { expect, type Page } from "@playwright/test"

const backendPort = process.env.VPW_PLAYWRIGHT_BACKEND_PORT ?? "18000"

export const backendBaseUrl = (
  process.env.VPW_E2E_BACKEND_URL ?? `http://127.0.0.1:${backendPort}`
).replace(/\/+$/, "")

export async function openWorkbench(page: Page): Promise<void> {
  await page.goto("/")
  await expect(page.getByRole("main")).toBeVisible()
}

export function localApiHeaders(): Record<string, string> {
  return {}
}
