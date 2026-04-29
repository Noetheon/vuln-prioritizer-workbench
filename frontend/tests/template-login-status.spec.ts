import { expect, test } from "@playwright/test"

test("template login reaches authenticated Workbench status shell", async ({
  page,
}) => {
  await page.goto("/login")

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
  await expect(page.getByText("Vuln Prioritizer Workbench")).toBeVisible()
  await page.getByLabel("Email").fill("admin@example.com")
  await page.getByLabel("Password").fill("changethis")
  await page.getByRole("button", { name: "Sign in" }).click()

  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByText("Backend adapter online")).toBeVisible()
  await expect(page.getByText("admin@example.com")).toBeVisible()
  const navigation = page.getByRole("navigation", {
    name: "Workbench navigation",
  })
  for (const label of [
    "Dashboard",
    "Projects",
    "Imports",
    "Findings",
    "Assets",
    "Providers",
    "Reports",
    "Settings",
  ]) {
    await expect(navigation.getByRole("link", { name: label })).toBeVisible()
  }
  const legacyMenuLabel = ["It", "ems"].join("")
  await expect(
    navigation.getByRole("link", { name: legacyMenuLabel }),
  ).toHaveCount(0)
  await expect(page.getByText(legacyMenuLabel, { exact: true })).toHaveCount(0)
  await expect(page.getByText("template-backend-adapter")).toBeVisible()
  await expect(page.getByText("disabled")).toBeVisible()
  await expect(
    page.getByRole("heading", { name: "Provider Status" }),
  ).toBeVisible()
  await expect(page.getByText("Snapshot mode")).toBeVisible()
  await expect(page.getByText("No snapshot recorded")).toBeVisible()
  const providerSources = page.getByLabel("Provider sources")
  await expect(providerSources.getByText("NVD", { exact: true })).toBeVisible()
  await expect(providerSources.getByText("EPSS", { exact: true })).toBeVisible()
  await expect(providerSources.getByText("KEV", { exact: true })).toBeVisible()
  await expect(
    page.getByRole("region", { name: "Dashboard empty state" }),
  ).toContainText("No projects yet")

  const accessToken = await page.evaluate(() =>
    window.localStorage.getItem("access_token"),
  )
  expect(accessToken).toBeTruthy()
  const authHeaders = { Authorization: `Bearer ${accessToken}` }
  const projectResponse = await page.request.post(
    "http://127.0.0.1:8000/api/v1/projects/",
    {
      data: {
        description: "Playwright dashboard summary project",
        name: "VPW Dashboard Project",
      },
      headers: authHeaders,
    },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = (await projectResponse.json()) as { id: string; name: string }

  await page.reload()
  await expect(page.getByLabel("Current project")).toHaveValue(project.id)
  await expect(
    page.getByRole("region", { name: "No findings empty state" }),
  ).toContainText(`No findings in ${project.name}`)
  await expect(page.getByLabel("Critical summary card")).toContainText("0")
  await expect(page.getByLabel("Latest Runs summary card")).toContainText(
    "No runs",
  )

  const importResponse = await page.request.post(
    `http://127.0.0.1:8000/api/v1/projects/${project.id}/imports`,
    {
      headers: authHeaders,
      multipart: {
        file: {
          buffer: Buffer.from("CVE-2021-44228\nCVE-2024-3094\n"),
          mimeType: "text/plain",
          name: "dashboard-cves.txt",
        },
        input_type: "cve-list",
      },
    },
  )
  expect(importResponse.ok()).toBeTruthy()

  await page.reload()
  await expect(page.getByLabel("Critical summary card")).toContainText("2")
  await expect(page.getByLabel("High summary card")).toContainText("0")
  await expect(page.getByLabel("KEV summary card")).toContainText(/[1-9]/)
  await expect(page.getByLabel("Latest Runs summary card")).toContainText(
    "succeeded",
  )
  await expect(
    page.getByRole("region", { name: "No findings empty state" }),
  ).toHaveCount(0)
  await expect(page.getByLabel("Project decision summary")).toContainText(
    "Total findings",
  )

  await navigation.getByRole("link", { name: "Projects" }).click()
  await expect(page).toHaveURL(/\/projects$/)
  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible()
  const createProjectForm = page.getByRole("region", {
    name: "Create Project form",
  })
  await expect(createProjectForm).toBeVisible()
  await createProjectForm
    .getByRole("button", { name: "Create Project" })
    .click()
  await expect(page.getByText("Project name is required.")).toBeVisible()
  await createProjectForm.getByLabel("Project name").fill("VPW UI Project")
  await createProjectForm
    .getByLabel("Description")
    .fill("Created through the Projects page E2E workflow")
  await createProjectForm
    .getByRole("button", { name: "Create Project" })
    .click()
  await expect(page.getByText("Project VPW UI Project created.")).toBeVisible()
  const projectsList = page.getByRole("region", { name: "Projects list" })
  await expect(projectsList.getByText("VPW UI Project")).toBeVisible()
  const projectDetail = page.getByRole("region", { name: "Project detail" })
  await expect(projectDetail).toContainText("VPW UI Project")
  await projectDetail.getByRole("button", { name: "Edit" }).click()
  await projectDetail
    .getByLabel("Edit project name")
    .fill("VPW UI Project Edited")
  await projectDetail
    .getByLabel("Edit description")
    .fill("Updated through the Projects page E2E workflow")
  await projectDetail.getByRole("button", { name: "Save Project" }).click()
  await expect(
    page.getByText("Project VPW UI Project Edited updated."),
  ).toBeVisible()
  await expect(projectDetail).toContainText("VPW UI Project Edited")
  await projectDetail.getByLabel("Confirm deletion for this project").check()
  await projectDetail.getByRole("button", { name: "Delete Project" }).click()
  await expect(
    page.getByText("Project VPW UI Project Edited deleted."),
  ).toBeVisible()
  await expect(projectsList.getByText("VPW UI Project Edited")).toHaveCount(0)

  await navigation.getByRole("link", { name: "Settings" }).click()
  await expect(page).toHaveURL(/\/settings$/)
  await expect(
    page.getByRole("heading", { exact: true, name: "Settings" }),
  ).toBeVisible()
  await expect(
    page.getByRole("region", { name: "User Settings" }),
  ).toContainText("admin@example.com")

  await page.getByRole("button", { name: "Sign out" }).click()
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
})
