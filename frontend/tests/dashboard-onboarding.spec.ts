import { expect, test } from "@playwright/test"
import { routeWorkbenchShell } from "./workbench-route-mocks"

test("a fresh install opens with the setup checklist", async ({ page }) => {
  await routeWorkbenchShell(page, { projects: [] })

  await page.goto("/")

  const checklist = page.getByRole("region", {
    name: "Set up your first project",
  })
  await expect(checklist).toContainText("0 of 4 steps done")
  await expect(
    checklist.getByRole("progressbar", { name: "0 of 4 setup steps done" }),
  ).toBeVisible()
  // Nothing to import into or report on until a project exists.
  await expect(checklist.getByRole("link")).toHaveCount(0)
  await expect(page.getByRole("link", { name: "Import findings" })).toHaveCount(
    0,
  )
  await expect(
    page.getByRole("link", { name: "Generate evidence" }),
  ).toHaveCount(0)

  await checklist.getByRole("button", { name: "Create project" }).click()
  const drawer = page.getByRole("dialog", { name: "Create project" })
  await expect(drawer.getByLabel("Project name")).toBeVisible()
  await drawer.getByRole("button", { name: "Create project" }).click()
  await expect(drawer).toContainText("Project name is required.")
})
