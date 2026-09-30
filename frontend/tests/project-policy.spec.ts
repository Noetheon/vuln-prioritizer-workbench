import { expect, test } from "@playwright/test"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

test("project policy saves a new version and re-evaluates findings", async ({
  page,
}) => {
  const updates: Record<string, unknown>[] = []
  await page.setViewportSize({ width: 1440, height: 900 })
  await routeWorkbenchShell(page, {
    onPolicyUpdate: (body) => updates.push(body),
    projects: [mockProject],
  })

  await page.goto("/projects")
  await page
    .getByRole("button", { name: `Settings for ${mockProject.name}` })
    .click()
  await page.getByRole("tab", { name: "Configuration" }).click()
  const card = page.getByRole("region", { name: "Priority policy" })
  await expect(card.getByText("Defaults", { exact: true })).toBeVisible()
  const save = card.getByRole("button", { name: "Save and re-evaluate" })
  await expect(save).toBeDisabled()
  await expect(card.getByText("7 days", { exact: true })).toBeVisible()

  await card.getByLabel("High EPSS threshold").fill("0.9")
  await expect(card.getByRole("alert")).toHaveText(
    "EPSS thresholds must descend from Critical to High to Medium.",
  )
  await expect(save).toBeDisabled()
  await card.getByLabel("High EPSS threshold").fill("0.4")
  await card.getByLabel("High CVSS threshold").fill("7.5")
  await card.getByLabel("High SLA hours").fill("48")
  await expect(card.getByText("2 days", { exact: true })).toBeVisible()
  await card.getByLabel("Reason (optional)").fill("Risk committee")
  await save.click()

  await expect(card.getByRole("status")).toHaveText(
    "Saved policy version 1. Findings are being re-evaluated with the new policy.",
  )
  await expect(card.getByText("Version 1", { exact: true })).toBeVisible()
  expect(updates).toEqual([
    {
      critical_cvss_threshold: 7,
      critical_epss_threshold: 0.7,
      high_cvss_threshold: 7.5,
      high_epss_threshold: 0.4,
      medium_cvss_threshold: 7,
      medium_epss_threshold: 0.1,
      sla_hours: { critical: 24, high: 48, low: 2160, medium: 720 },
    },
  ])
  await expect(save).toBeDisabled()
  await card.getByRole("button", { name: "Use defaults" }).click()
  await expect(card.getByLabel("High CVSS threshold")).toHaveValue("9")
  await expect(save).toBeEnabled()
})

test("the priority policy has its own page, linked from a finding's SLA", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto(`/findings/${mockFinding.id}?projectId=${mockProject.id}`)
  await page
    .getByRole("region", { name: "Finding decision summary" })
    .getByTitle("Thresholds and SLA targets come from the project's priority policy")
    .click()
  await expect(page).toHaveURL(
    new RegExp(`/policy\\?projectId=${mockProject.id}$`),
  )
  await expect(
    page.getByRole("heading", { level: 1, name: "Priority Policy" }),
  ).toBeVisible()
  const card = page.getByRole("region", { name: "Priority policy" })
  await expect(card.getByText("Defaults", { exact: true })).toBeVisible()
  await expect(
    page
      .getByRole("navigation", { name: "Workbench navigation" })
      .getByRole("link", { name: "Priority Policy" }),
  ).toHaveAttribute("aria-current", "page")
})

test("paths from before the rename redirect and keep their filters", async ({
  page,
}) => {
  await routeWorkbenchShell(page, { projects: [mockProject] })

  await page.goto(`/findings?projectId=${mockProject.id}&priority=critical`)
  await expect(page).toHaveURL(
    new RegExp(`/triage\\?projectId=${mockProject.id}&priority=critical$`),
  )
  await expect(
    page.getByRole("heading", { level: 1, name: "Triage" }),
  ).toBeVisible()

  await page.goto("/reports")
  await expect(page).toHaveURL(/\/evidence(?:\?.*)?$/)
  await page.goto("/waivers")
  await expect(page).toHaveURL(/\/risk-acceptance(?:\?.*)?$/)
  await page.goto("/providers")
  await expect(page).toHaveURL(/\/data-sources(?:\?.*)?$/)
})
