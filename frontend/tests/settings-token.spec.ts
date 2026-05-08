import { expect, test } from "@playwright/test"
import { login } from "./auth-helpers"

test("workbench settings clears one-time API token when leaving settings", async ({
  page,
}) => {
  const testRunSuffix = Date.now().toString(36)

  await login(page)

  await page.goto("/settings")
  await expect(
    page.getByRole("heading", { name: "Service Token" }),
  ).toBeVisible()
  await page.getByLabel("Name").fill(`automation-${testRunSuffix}`)
  const importScope = page.getByRole("checkbox", { name: /IMPORT/i })
  await importScope.focus()
  await page.keyboard.press("Space")
  await expect(importScope).toBeChecked()
  const reportScope = page.getByRole("checkbox", { name: /REPORT/i })
  await reportScope.focus()
  await page.keyboard.press("Space")
  await expect(reportScope).toBeChecked()
  await page.getByRole("button", { name: "Create Token" }).click()

  const createdTokenPanel = page.getByRole("region", {
    name: "Created API token",
  })
  await expect(createdTokenPanel).toBeVisible()
  await expect(createdTokenPanel.getByLabel("Token")).toHaveValue(/^vpr_/)
  await expect(createdTokenPanel).toContainText("READ, IMPORT, REPORT")

  await page.getByRole("link", { name: "Dashboard" }).click()
  await page.getByRole("link", { name: "Settings" }).click()

  await expect(createdTokenPanel).toHaveCount(0)
  await expect(page.getByRole("textbox", { name: "Token" })).toHaveCount(0)
  await expect(
    page.getByRole("table", { name: "API tokens table" }),
  ).toContainText(/READ\s*IMPORT\s*REPORT/)
})
