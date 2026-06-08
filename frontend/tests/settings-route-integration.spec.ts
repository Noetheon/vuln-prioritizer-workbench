import { expect, test } from "@playwright/test"

import { mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

test("settings provider link preserves selected project context", async ({
  page,
}) => {
  await routeWorkbenchShell(page, { projects: [mockProject] })

  await page.goto(`/settings?projectId=${mockProject.id}`)

  const providersLink = page.getByRole("link", { name: "View providers" })
  await expect(providersLink).toHaveAttribute(
    "href",
    `/providers?projectId=${mockProject.id}`,
  )

  await providersLink.click()

  await expect(page).toHaveURL(
    new RegExp(`/providers\\?projectId=${mockProject.id}`),
  )
})

test("settings links API Explorer to runtime backend docs", async ({ page }) => {
  await routeWorkbenchShell(page, {
    apiDocsPath: "/internal/docs",
    projects: [mockProject],
  })

  await page.goto("/settings")

  await expect(page.getByRole("link", { name: "API Explorer" })).toHaveAttribute(
    "href",
    "/internal/docs",
  )
})

test("settings hides API Explorer when backend docs are disabled", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    apiDocsEnabled: false,
    apiDocsPath: null,
    projects: [mockProject],
  })

  await page.goto("/settings")

  await expect(page.getByRole("link", { name: "API Explorer" })).toHaveCount(0)
})

test("settings overview exposes about and worker health facts", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    demoWorkspaceEnabled: true,
    projects: [mockProject],
  })

  await page.goto("/settings")

  await expect(page.getByText("Frontend 1.1.0; backend demo.").first()).toBeVisible()
  await expect(page.getByText("workbench-status.v1").first()).toBeVisible()
  await expect(
    page.getByText("Environment local; demo workspace enabled.").first(),
  ).toBeVisible()
  await expect(page.getByText("Workflow worker").first()).toBeVisible()
  await expect(page.getByText("Service workflow-worker").first()).toBeVisible()
})

test("settings diagnostics exposes launcher diagnostics command", async ({
  page,
}) => {
  await routeWorkbenchShell(page, { projects: [mockProject] })

  await page.goto("/settings?tab=diagnostics")

  await expect(page.getByText("Frontend version")).toBeVisible()
  await expect(page.getByText("Runtime mode")).toBeVisible()
  await expect(page.getByText("Diagnostics bundle")).toBeVisible()
  await expect(
    page.getByText("scripts/launch-workbench.sh diagnostics").first(),
  ).toBeVisible()
  await expect(
    page.getByText("launch-workbench.ps1 diagnostics"),
  ).toBeVisible()
})
