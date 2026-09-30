import { expect, type Page, test } from "@playwright/test"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

const identityProject = {
  ...mockProject,
  id: "project-2",
  name: "Identity Platform",
}

function projectSwitcher(page: Page) {
  return page.getByRole("combobox", { exact: true, name: "Project" })
}

async function switchProject(page: Page, projectName: string) {
  await projectSwitcher(page).click()
  await page.getByRole("option", { exact: true, name: projectName }).click()
}

test("the header switcher changes project and keeps the Triage filters", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject, identityProject],
  })

  await page.goto(
    `/triage?projectId=${mockProject.id}&priority=critical&offset=25`,
  )
  await expect(projectSwitcher(page)).toContainText(mockProject.name)
  // Triage has no project field of its own any more.
  await expect(
    page.getByRole("region", { name: "Findings filters" }).getByRole("combobox", {
      name: "Project",
    }),
  ).toHaveCount(0)

  await switchProject(page, identityProject.name)

  await expect(projectSwitcher(page)).toContainText(identityProject.name)
  await expect(page).toHaveURL(/\/triage\?/)
  const url = new URL(page.url())
  expect(url.searchParams.get("projectId")).toBe(identityProject.id)
  expect(url.searchParams.get("priority")).toBe("critical")
  expect(url.searchParams.has("offset")).toBe(false)

  // The choice holds on every page.
  await page
    .getByRole("navigation", { name: "Workbench navigation" })
    .getByRole("link", { name: "Assets" })
    .click()
  await expect(page).toHaveURL(/\/assets\?projectId=project-2$/)
  await expect(projectSwitcher(page)).toContainText(identityProject.name)
})

test("switching project on a finding page returns to Triage", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject, identityProject],
  })

  await page.goto(`/findings/${mockFinding.id}?projectId=${mockProject.id}`)
  await expect(projectSwitcher(page)).toContainText(mockProject.name)

  await switchProject(page, identityProject.name)

  await expect(page).toHaveURL(/\/triage\?projectId=project-2$/)
  await expect(
    page.getByRole("heading", { level: 1, name: "Triage" }),
  ).toBeVisible()
})
