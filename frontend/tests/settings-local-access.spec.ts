import { expect, test } from "@playwright/test"
import { openWorkbench } from "./workbench-runtime-helpers"

test("workbench settings uses local access and hides API token management", async ({
  page,
}) => {
  await openWorkbench(page)

  await page.goto("/settings?tab=tokens")

  await expect(
    page.getByRole("heading", { level: 1, name: "Settings" }),
  ).toBeVisible()
  await expect(page.getByRole("tab", { name: "Overview" })).toBeVisible()
  await expect(
    page.getByRole("tab", { name: "Runtime & Providers" }),
  ).toBeVisible()
  await expect(page.getByRole("tab", { name: "Diagnostics" })).toBeVisible()
  await expect(page).toHaveURL(/\/settings(?:\?[^#]*)?$/)
  expect(new URL(page.url()).searchParams.has("tab")).toBe(false)

  await expect(page.getByRole("tab", { name: "API " + "Tokens" })).toHaveCount(
    0,
  )
  await expect(
    page.getByRole("region", { exact: true, name: "API " + "tokens" }),
  ).toHaveCount(0)
  await expect(
    page.getByRole("button", { name: "Create " + "token" }),
  ).toHaveCount(0)
  await expect(
    page.getByRole("table", { name: "API " + "tokens table" }),
  ).toHaveCount(0)
})
