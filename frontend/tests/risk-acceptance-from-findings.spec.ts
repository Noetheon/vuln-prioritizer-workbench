import { expect, type Page, test } from "@playwright/test"
import {
  mockAsset,
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

function queueFinding(index: number) {
  return {
    ...mockFinding,
    asset_key: `payments-api-${index}`,
    asset_name: `payments-api-${index}`,
    cve_id: `CVE-2024-${String(1000 + index)}`,
    id: `finding-${index}`,
    risk_score: 90 - index,
  }
}

async function fillDecision(page: Page) {
  const sheet = page.getByRole("dialog", { name: "Accept risk" })
  await sheet.getByLabel("Acceptance owner").fill("risk-owner")
  await sheet
    .getByLabel("Acceptance reason")
    .fill("Compensating controls are in place until the vendor fix ships.")
  await sheet.getByLabel("Acceptance approval reference").fill("CAB-101")
  return sheet
}

test("a finding's risk is accepted from its detail page", async ({ page }) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })
  const created: Record<string, unknown>[] = []
  await page.route(
    `**/api/v1/projects/${mockProject.id}/waivers/`,
    async (route) => {
      if (route.request().method() !== "POST") return route.fallback()
      const body = route.request().postDataJSON() as Record<string, unknown>
      created.push(body)
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          ...body,
          created_at: "2026-06-06T10:00:00Z",
          days_remaining: 30,
          id: "waiver-new",
          matched_findings: 1,
          project_id: mockProject.id,
          status: "active",
          updated_at: "2026-06-06T10:00:00Z",
        }),
      })
    },
  )

  await page.goto(`/findings/${mockFinding.id}?projectId=${mockProject.id}`)
  await page.getByRole("button", { name: "Accept risk…" }).click()

  const sheet = await fillDecision(page)
  // The finding is the scope: no UUID to type.
  await expect(sheet.getByRole("list", { name: "Findings to accept" })).toContainText(
    "CVE-2024-3094",
  )
  await expect(sheet.getByLabel("Acceptance finding ID")).toHaveCount(0)
  await sheet.getByRole("button", { exact: true, name: "Accept risk" }).click()

  await expect(sheet).toBeHidden()
  await expect(
    page.getByText("Accepted risk recorded for 1 finding."),
  ).toBeVisible()
  expect(created).toHaveLength(1)
  expect(created[0]).toMatchObject({
    approval_ref: "CAB-101",
    cve_id: "CVE-2024-3094",
    finding_id: mockFinding.id,
    owner: "risk-owner",
  })
})

test("selected Triage rows are accepted together", async ({ page }) => {
  const findings = [queueFinding(1), queueFinding(2), queueFinding(3)]
  await routeWorkbenchShell(page, { findings, projects: [mockProject] })
  const bulkRequests: Record<string, unknown>[] = []
  await page.route(
    `**/api/v1/projects/${mockProject.id}/waivers/bulk`,
    async (route) => {
      const body = route.request().postDataJSON() as { finding_ids: string[] }
      bulkRequests.push(body)
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ count: body.finding_ids.length, data: [] }),
      })
    },
  )

  await page.goto(`/triage?projectId=${mockProject.id}`)
  await page.getByRole("checkbox", { name: /Select CVE-2024-1001/ }).check()
  await page.getByRole("checkbox", { name: /Select CVE-2024-1003/ }).check()
  await page.getByRole("button", { name: "Accept risk…" }).click()

  const sheet = await fillDecision(page)
  const chosen = sheet.getByRole("list", { name: "Findings to accept" })
  await expect(chosen.getByRole("listitem")).toHaveCount(2)
  await expect(chosen).toContainText("CVE-2024-1001")
  await expect(chosen).toContainText("CVE-2024-1003")
  await sheet
    .getByRole("button", { name: "Accept risk for 2 findings" })
    .click()

  await expect(sheet).toBeHidden()
  const bulkBar = page.getByRole("region", { name: "Bulk status change" })
  await expect(bulkBar).toContainText("Accepted risk recorded for 2 findings.")
  expect(bulkRequests).toHaveLength(1)
  expect(bulkRequests[0]).toMatchObject({
    approval_ref: "CAB-101",
    finding_ids: ["finding-1", "finding-3"],
    owner: "risk-owner",
  })
})

test("the acceptance form picks findings and assets instead of UUIDs", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    assets: [mockAsset],
    findings: [mockFinding],
    projects: [mockProject],
  })
  const created: Record<string, unknown>[] = []
  await page.route(
    `**/api/v1/projects/${mockProject.id}/waivers/`,
    async (route) => {
      if (route.request().method() !== "POST") return route.fallback()
      created.push(route.request().postDataJSON() as Record<string, unknown>)
      return route.fallback()
    },
  )

  await page.goto(`/risk-acceptance?projectId=${mockProject.id}`)
  await page
    .getByRole("button", { name: "Record accepted risk" })
    .first()
    .click()
  const drawer = page.getByRole("dialog", { name: "Record accepted risk" })
  await expect(drawer.getByLabel("Acceptance finding ID")).toHaveCount(0)
  await expect(drawer.getByLabel("Acceptance asset ID")).toHaveCount(0)

  await drawer
    .getByRole("combobox", { exact: true, name: "Acceptance finding" })
    .click()
  await page
    .getByRole("option", { name: /CVE-2024-3094 · xz 5\.6\.0 · build-host-1/ })
    .click()
  // Choosing a finding fills its CVE for the register.
  await expect(drawer.getByLabel("Acceptance CVE ID")).toHaveValue(
    "CVE-2024-3094",
  )
  await drawer
    .getByRole("combobox", { exact: true, name: "Acceptance asset" })
    .click()
  await page.getByRole("option", { name: "build-host-1" }).click()

  await drawer.getByLabel("Acceptance owner").fill("risk-owner")
  await drawer
    .getByLabel("Acceptance reason")
    .fill("Accepted while the build host is rebuilt.")
  await drawer.getByRole("button", { name: "Create acceptance" }).click()

  await expect.poll(() => created.length).toBe(1)
  expect(created[0]).toMatchObject({
    asset_id: mockAsset.id,
    cve_id: "CVE-2024-3094",
    finding_id: mockFinding.id,
  })
})
