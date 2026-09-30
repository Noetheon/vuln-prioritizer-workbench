import { expect, test } from "@playwright/test"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

const laptop = { width: 1280, height: 800 }

function queueFinding(index: number, overrides = {}) {
  return {
    ...mockFinding,
    asset_key: `payments-api-${index}`,
    asset_name: `payments-api-${index}`,
    cve_id: `CVE-2024-${String(1000 + index)}`,
    id: `finding-${index}`,
    owner: "team-payments-platform",
    risk_score: 99 - index,
    sla: { label: "Emergency", target_hours: 24 },
    sla_due_at: "2026-03-22T10:00:00Z",
    sla_state: "overdue" as const,
    ...overrides,
  }
}

test("the queue fits a 1,280 px laptop screen with every row action in view", async ({
  page,
}) => {
  await page.setViewportSize(laptop)
  await routeWorkbenchShell(page, {
    findings: [queueFinding(1), queueFinding(2), queueFinding(3)],
    projects: [mockProject],
  })

  await page.goto(`/triage?projectId=${mockProject.id}`)
  const table = page.getByRole("region", {
    name: "Findings table scroll region",
  })
  await expect(table).toContainText("CVE-2024-1001")

  const overflow = await table.evaluate(
    (element) => element.scrollWidth - element.clientWidth,
  )
  expect(overflow).toBeLessThanOrEqual(1)
  await expect(
    page.getByRole("button", { name: /Quick view CVE-2024-1001/ }),
  ).toBeInViewport()

  // Priority and score share one column and are never cut short.
  const priorityCell = table
    .locator("tbody tr")
    .filter({ hasText: "CVE-2024-1001" })
    .locator("td")
    .nth(1)
  await expect(priorityCell).toContainText("Critical")
  await expect(priorityCell).toContainText("98.0")
  const clipped = await priorityCell
    .locator(".vpw-badge__label")
    .evaluateAll((labels) =>
      labels.filter((label) => label.scrollWidth > label.clientWidth).length,
    )
  expect(clipped).toBe(0)
  // Score keeps its own sort control next to Priority.
  await expect(
    page.getByRole("button", { name: "Sort by Score" }),
  ).toBeVisible()
  await expect(
    page.getByRole("button", { name: "Sort by Priority" }),
  ).toBeVisible()
})

test("SLA targets read in days, the date is labelled, and closed findings are not ranked", async ({
  page,
}) => {
  await page.setViewportSize(laptop)
  await routeWorkbenchShell(page, {
    findings: [
      queueFinding(1),
      queueFinding(2, {
        risk_score: 0,
        sla: { label: "Verification" },
        sla_due_at: null,
        sla_state: null,
        status: "fixed",
      }),
    ],
    projects: [mockProject],
  })

  await page.goto(`/triage?projectId=${mockProject.id}&status=all`)
  const rows = page
    .getByRole("region", { name: "Findings table scroll region" })
    .locator("tbody tr")
  await expect(rows).toHaveCount(2)

  const open = rows.filter({ hasText: "CVE-2024-1001" })
  await expect(open).toContainText("SLA Emergency · 1 day")
  await expect(open).toContainText("Overdue since")
  await expect(open).toContainText("Last seen")
  await expect(open).not.toContainText("24h")

  const fixed = rows.filter({ hasText: "CVE-2024-1002" })
  await expect(fixed).toContainText("Fixed")
  await expect(fixed).toContainText("Last seen")
  // No score badge: the priority cell holds only the muted priority.
  await expect(fixed.locator("td").nth(1)).toHaveText("Critical")
  await expect(fixed).not.toContainText("Verification")
})

test("choosing a view keeps the filters already set", async ({ page }) => {
  await page.setViewportSize(laptop)
  await routeWorkbenchShell(page, {
    findings: [queueFinding(1)],
    projects: [mockProject],
  })

  await page.goto(
    `/triage?projectId=${mockProject.id}&priority=critical&status=open`,
  )
  await expect(
    page.getByRole("region", { name: "Findings table scroll region" }),
  ).toContainText("CVE-2024-1001")

  await page.getByRole("combobox", { name: "Finding view" }).click()
  await page.getByRole("option", { exact: true, name: "Overdue" }).click()

  await expect(page).toHaveURL(/sla=overdue/)
  const url = new URL(page.url())
  expect(url.searchParams.get("priority")).toBe("critical")
  expect(url.searchParams.get("status")).toBe("open")
  await expect(page.getByText("Priority: Critical")).toBeVisible()
  await expect(page.getByText("Status: Open")).toBeVisible()
})

test("bulk actions stay in view while rows further down are chosen", async ({
  page,
}) => {
  await page.setViewportSize(laptop)
  await routeWorkbenchShell(page, {
    findings: Array.from({ length: 25 }, (_, index) =>
      queueFinding(index + 1),
    ),
    projects: [mockProject],
  })

  await page.goto(`/triage?projectId=${mockProject.id}&limit=25`)
  const lastRowCheckbox = page.getByRole("checkbox", {
    name: /Select CVE-2024-1025/,
  })
  await lastRowCheckbox.scrollIntoViewIfNeeded()
  await lastRowCheckbox.check()

  const bulkBar = page.getByRole("region", { name: "Bulk status change" })
  await expect(bulkBar).toContainText("1 finding selected")
  await expect(bulkBar).toBeInViewport()

  // Scrolling back to the top keeps the choice in sight.
  await page
    .getByRole("checkbox", { name: /Select CVE-2024-1001/ })
    .scrollIntoViewIfNeeded()
  await page.getByRole("checkbox", { name: /Select CVE-2024-1001/ }).check()
  await expect(bulkBar).toContainText("2 findings selected")
  await expect(bulkBar).toBeInViewport()
})
