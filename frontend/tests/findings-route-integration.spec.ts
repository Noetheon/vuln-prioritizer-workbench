import { expect, type Page, test } from "@playwright/test"

async function routeWorkbenchShell(page: Page) {
  await page.addInitScript(() => {
    // biome-ignore lint/suspicious/noDocumentCookie: Playwright sets a mock readable CSRF cookie before app boot.
    document.cookie = "vpw_csrf_token=mock-csrf; Path=/; SameSite=Strict"
  })

  await page.route("**/api/v1/users/me", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        id: "demo-user",
        email: "admin@example.com",
        full_name: "Admin",
        is_active: true,
        is_superuser: true,
        created_at: "2025-01-01T00:00:00Z",
      }),
    }),
  )
  await page.route("**/api/v1/workbench/status", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        app: "Vuln Prioritizer Workbench",
        status: "ok",
        core_package: "vuln_prioritizer",
        core_version: "demo",
      }),
    }),
  )
  await page.route("**/api/v1/providers/status", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        status: "ok",
        snapshot_mode: "demo",
        cache_age_seconds: 0,
        last_sync: "2025-04-30T10:00:00Z",
        warnings: [],
        snapshot: {
          id: "demo",
          mode: "demo",
          missing: false,
          selected_sources: ["epss", "kev"],
        },
        sources: [],
      }),
    }),
  )
  await page.route("**/api/v1/utils/health-check/", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ status: "ok" }),
    }),
  )
  await page.route("**/api/v1/projects/", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: [], count: 0 }),
    }),
  )
  await page.route("**/api/v1/projects/?*", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: [], count: 0 }),
    }),
  )
}

test("findings route renders the empty live queue without demo data", async ({
  page,
}) => {
  await routeWorkbenchShell(page)
  await page.goto("/findings")

  await expect(page.getByText("Demo preview")).toHaveCount(0)
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()

  await expect(page.getByText("Finding Decisions")).toHaveCount(0)
  await expect(page.getByText("Provider Status")).toHaveCount(0)
  await expect(page.getByText("Evidence Flow")).toHaveCount(0)

  await expect(page.getByText("No projects yet")).toBeVisible()
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toHaveCount(0)

  await expect(
    page.getByRole("combobox", { name: "Sort direction" }),
  ).toHaveCount(0)

  const sidebar = page.getByLabel("Workbench sidebar")
  await expect(sidebar).toHaveCSS("width", "248px")
  await expect(page.getByText("Sign out")).toHaveCount(0)
  await page.getByRole("button", { name: "Account menu" }).click()
  await expect(page.getByRole("menuitem", { name: "Sign out" })).toBeVisible()
  await page.keyboard.press("Escape")
  await page.getByRole("button", { name: "Collapse sidebar" }).click()
  await expect(sidebar).toHaveCSS("width", "72px")
  await expect(
    page.getByRole("button", { name: "Expand sidebar" }),
  ).toBeVisible()
  await expect(
    page
      .getByRole("navigation", { name: "Workbench navigation" })
      .getByText("Dashboard"),
  ).toHaveCount(0)
})

test("finding detail API errors do not fall back to demo findings", async ({
  page,
}) => {
  await routeWorkbenchShell(page)
  await page.route("**/api/v1/findings/demo-f1", (route) =>
    route.fulfill({
      contentType: "application/json",
      status: 404,
      body: JSON.stringify({ detail: "Finding not found" }),
    }),
  )

  await page.goto("/findings/demo-f1")

  await expect(page.getByText("Finding detail unavailable")).toBeVisible()
  await expect(page.getByText("Demo preview")).toHaveCount(0)
  await expect(page.getByText("CVE-2024-3094")).toHaveCount(0)
})
