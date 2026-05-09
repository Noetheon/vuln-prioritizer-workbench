import { expect, test } from "@playwright/test"
import { authHeaders, login } from "./auth-helpers"

test("workbench settings clears one-time API token when leaving settings", async ({
  page,
}) => {
  const testRunSuffix = Date.now().toString(36)

  const accessToken = await login(page)
  const projectName = `VPW Settings Token ${testRunSuffix}`
  const projectResponse = await page.request.post(
    "http://127.0.0.1:8000/api/v1/projects/",
    {
      data: {
        description: "Playwright settings token project",
        name: projectName,
      },
      headers: authHeaders(accessToken),
    },
  )
  expect(projectResponse.ok(), await projectResponse.text()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string; name: string }

  await page.goto(`/settings?projectId=${project.id}`)
  await expect(
    page.getByRole("heading", { name: "Service Token" }),
  ).toBeVisible()
  const projectScope = page.getByRole("combobox", { name: "Project scope" })
  await expect(projectScope).toBeEnabled()
  await expect(projectScope).toContainText(project.name)
  const tokenForm = page.getByLabel("Name").locator("xpath=ancestor::form[1]")
  const writeScope = tokenForm.getByRole("checkbox", { name: /WRITE/i })
  await expect(writeScope).not.toBeChecked()
  await tokenForm.getByText("WRITE", { exact: true }).click()
  await expect(writeScope).toBeChecked()
  await tokenForm.getByText("WRITE", { exact: true }).click()
  await expect(writeScope).not.toBeChecked()
  await page.getByLabel("Name").fill(`automation-${testRunSuffix}`)
  const importScope = tokenForm.getByRole("checkbox", { name: /IMPORT/i })
  await importScope.focus()
  await page.keyboard.press("Space")
  await expect(importScope).toBeChecked()
  const reportScope = tokenForm.getByRole("checkbox", { name: /REPORT/i })
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
  await expect(page).toHaveURL(/\/(?:\?.*)?$/)
  await expect(
    page.getByRole("heading", { name: "Risk Operations", level: 1 }),
  ).toBeVisible()
  await page.getByRole("link", { name: "Settings" }).click()
  await expect(
    page.getByRole("heading", { name: "Settings", level: 1 }),
  ).toBeVisible()

  await expect(createdTokenPanel).toHaveCount(0)
  await expect(page.getByRole("textbox", { name: "Token" })).toHaveCount(0)
  await expect(
    page.getByRole("table", { name: "API tokens table" }),
  ).toContainText(/READ\s*IMPORT\s*REPORT/)
})
