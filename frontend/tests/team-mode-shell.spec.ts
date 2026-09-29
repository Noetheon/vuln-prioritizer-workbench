import { expect, test } from "@playwright/test"
import { mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

const teamSession = {
  auth_mode: "proxy" as const,
  display_name: "Alice Example",
  logout_url: "/oauth2/sign_out",
  user: "alice@example.com",
  user_id: "7b8e7a9c-0d5c-5a55-9d2b-9a6f0d1c2e3f",
}

test("team mode shows the signed-in user and the proxy sign-out", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    session: teamSession,
  })

  await page.goto("/projects")
  const sidebar = page.getByRole("complementary", { name: "Workbench sidebar" })
  const identity = sidebar.getByLabel("Signed in as alice@example.com")
  await expect(identity).toContainText("Alice Example")
  await expect(sidebar.getByLabel("Local workspace status")).toHaveCount(0)
  await expect(sidebar.getByRole("link", { name: "Sign out" })).toHaveAttribute(
    "href",
    "/oauth2/sign_out",
  )
})

test("local mode keeps the workspace label without a sign-out", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await routeWorkbenchShell(page, { projects: [mockProject] })

  await page.goto("/projects")
  const sidebar = page.getByRole("complementary", { name: "Workbench sidebar" })
  await expect(sidebar.getByLabel("Local workspace status")).toContainText(
    "Local workspace",
  )
  await expect(sidebar.getByRole("link", { name: "Sign out" })).toHaveCount(0)
})
