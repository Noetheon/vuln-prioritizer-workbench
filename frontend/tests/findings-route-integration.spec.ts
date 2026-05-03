import { expect, type Page, test } from "@playwright/test"

async function routeWorkbenchShell(page: Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem("access_token", "demo-token")
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
        legacy_api_prefix: "/api",
        migration: {
          phase: "ready",
          legacy_workbench_mounted: false,
        },
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

test("findings route renders only the polished remediation queue", async ({
  page,
}) => {
  await routeWorkbenchShell(page)
  await page.goto("/findings")

  await expect(page.getByText("Demo preview").first()).toBeVisible()
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()

  await expect(page.getByText("Finding Decisions")).toHaveCount(0)
  await expect(page.getByText("Provider Status")).toHaveCount(0)
  await expect(page.getByText("Evidence Flow")).toHaveCount(0)

  const queue = page.getByRole("table", {
    name: "Findings remediation queue",
  })
  await expect(queue).toBeVisible()

  for (const column of [
    /Priority/i,
    /Score/i,
    /CVE/i,
    "Component / Service",
    "Owner",
    /Status/i,
    /Signals/i,
    "Why now",
    "View",
  ]) {
    await expect(
      queue.getByRole("columnheader", { name: column }),
    ).toBeVisible()
  }

  await expect(
    page.getByRole("combobox", { name: "Sort direction" }),
  ).toHaveCount(0)
  await expect(
    page.getByRole("button", { name: /Sort by Score/i }),
  ).toBeVisible()
  await page.getByRole("button", { name: /Sort by Score/i }).click()
  await expect(
    queue.getByRole("columnheader", { name: /Sort by Score/i }),
  ).toHaveAttribute("aria-sort", "descending")
  await page.getByRole("button", { name: /Sort by Score/i }).click()
  await expect(
    queue.getByRole("columnheader", { name: /Sort by Score/i }),
  ).toHaveAttribute("aria-sort", "ascending")

  await expect(queue.getByText("EPSS").first()).toBeVisible()
  await expect(queue.getByText("CVSS").first()).toBeVisible()
  await expect(
    page.getByRole("button", { name: /Quick view CVE-2024-3400/i }),
  ).toBeVisible()

  const tableWrapBefore = await page
    .locator(".remediation-table-wrap")
    .boundingBox()
  const tableBox = await queue.boundingBox()
  const actionBox = await page
    .getByRole("button", { name: /Quick view CVE-2024-3400/i })
    .boundingBox()
  expect(tableBox).not.toBeNull()
  expect(actionBox).not.toBeNull()
  if (tableBox && actionBox) {
    expect(actionBox.x + actionBox.width).toBeLessThanOrEqual(
      tableBox.x + tableBox.width + 1,
    )
  }

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
  const tableWrapAfter = await page
    .locator(".remediation-table-wrap")
    .boundingBox()
  expect(tableWrapBefore).not.toBeNull()
  expect(tableWrapAfter).not.toBeNull()
  if (tableWrapBefore && tableWrapAfter) {
    expect(tableWrapAfter.width).toBeGreaterThan(tableWrapBefore.width + 100)
  }
})
