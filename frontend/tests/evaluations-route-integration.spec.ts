import { mkdir, writeFile } from "node:fs/promises"
import { expect, test } from "@playwright/test"
import { validCveList, waitForRunSucceeded } from "./workbench-e2e-helpers"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"
import { backendBaseUrl, localApiHeaders } from "./workbench-runtime-helpers"

test("reevaluation selects provider evidence explicitly and reports legacy conflicts", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })
  let submitted: unknown
  await page.route(
    `**/api/v1/projects/${mockProject.id}/evaluations`,
    async (route) => {
      submitted = route.request().postDataJSON()
      await route.fulfill({
        status: 409,
        contentType: "application/json",
        body: JSON.stringify({
          detail:
            "Stored replay inputs are unavailable. Import fresh evidence.",
        }),
      })
    },
  )
  await page.goto(`/findings/${mockFinding.id}?projectId=${mockProject.id}`)
  await page.getByRole("button", { name: "Re-evaluate", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Re-evaluate this finding" })
  await expect(dialog).toContainText("does not perform a new scan")
  await dialog.getByLabel("Reason (optional)").fill("Review evidence")
  await dialog.getByRole("button", { name: "Start re-evaluation" }).click()
  await expect(dialog.getByRole("alert")).toContainText("Import fresh evidence")
  expect(submitted).toEqual({
    finding_ids: [mockFinding.id],
    reason: "Review evidence",
  })
  await dialog.getByLabel("Provider evidence").click()
  await page
    .getByRole("option", { name: "Use latest provider snapshot" })
    .click()
  await dialog.getByRole("button", { name: "Start re-evaluation" }).click()
  await expect
    .poll(() => submitted)
    .toEqual({
      finding_ids: [mockFinding.id],
      provider_snapshot_id: "demo",
      reason: "Review evidence",
    })
})

test("history renders recorded provenance and adjacent decision differences on mobile", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })
  const old = {
    id: "revision-1",
    analysis_run_id: "run-1",
    evaluated_at: "2026-01-01T00:00:00Z",
    observed_at: "2025-12-30T00:00:00Z",
    cause: "import",
    replay_status: "legacy_unavailable",
    priority: "High",
    status: "open",
    risk_score: 50,
    operational_rank: 1,
    rationale: "Recorded initial facts",
    recommended_action: "Review scope",
    is_current: false,
    changed_fields: [],
  }
  const latest = {
    ...old,
    id: "revision-2",
    evaluated_at: "2026-01-02T00:00:00Z",
    cause: "provider_refresh",
    replay_status: "available",
    priority: "Critical",
    risk_score: 80,
    is_current: true,
    engine_version: "decision-engine.v1",
    changed_fields: ["priority", "risk_score"],
  }
  await page.route("**/api/v1/findings/*/decision-revisions?*", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: [latest, old], count: 2 }),
    }),
  )
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`/findings/${mockFinding.id}?projectId=${mockProject.id}`)
  await page.getByRole("tab", { name: "History", exact: true }).click()
  const history = page.getByRole("region", {
    name: "Decision revisions",
    exact: true,
  })
  await expect(history).toContainText("Unavailable for this legacy revision")
  await expect(history).toContainText("Last observed")
  await expect(history.locator("article").first()).toHaveCSS("padding", "16px")
  await history.getByText("Changes from previous revision (3)").click()
  await expect(history).toContainText("50 → 80")
  await expect(history).toContainText("High → Critical")
  const cardBox = await history.locator("article").first().boundingBox()
  expect(cardBox?.x).toBeGreaterThanOrEqual(0)
  expect((cardBox?.x ?? 0) + (cardBox?.width ?? 0)).toBeLessThanOrEqual(390)
  expect(
    await page.evaluate(
      () =>
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
    ),
  ).toBeLessThanOrEqual(1)
  await mkdir("/tmp/vpw-evaluation-ui", { recursive: true })
  await page.screenshot({
    path: "/tmp/vpw-evaluation-ui/revision-history-mobile.png",
    fullPage: true,
  })
})

test("GitHub preview is reviewable and creates only the explicitly scoped issue", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })
  const issue = {
    finding_id: mockFinding.id,
    cve_id: mockFinding.cve_id,
    title: "Patch xz on build-host-1",
    body: "Recorded finding scope and evidence.",
    duplicate_key: "scope-1",
    labels: ["security"],
  }
  let exported: unknown
  await page.route("**/github/issues/preview", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: [issue], count: 1, dry_run: true }),
    }),
  )
  await page.route("**/github/issues/export", (route) => {
    exported = route.request().postDataJSON()
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        data: [
          {
            ...issue,
            status: "created",
            issue_url: "https://github.com/example/security/issues/1",
          },
        ],
        count: 1,
        created_count: 1,
        dry_run: false,
      }),
    })
  })
  await page.goto(`/findings/${mockFinding.id}?projectId=${mockProject.id}`)
  await page.getByRole("button", { name: "Preview GitHub issue" }).click()
  const dialog = page.getByRole("dialog", { name: "GitHub issue preview" })
  await expect(dialog.getByLabel("Prepared issue Markdown")).toContainText(
    issue.body,
  )
  expect(exported).toBeUndefined()
  await expect(
    dialog.getByRole("button", { name: "Create GitHub issue", exact: true }),
  ).toBeDisabled()
  await dialog.getByLabel("Repository (owner/name)").fill("example/security")
  await dialog
    .getByRole("button", { name: "Create GitHub issue in example/security" })
    .click()
  await expect(dialog.getByRole("status")).toContainText("Issue created")
  expect(exported).toEqual({
    finding_ids: [mockFinding.id],
    repository: "example/security",
    dry_run: false,
  })
})

test("a real native evaluation appends history while preserving observation time", async ({
  page,
}) => {
  test.setTimeout(120_000)
  const errors: string[] = []
  page.on("pageerror", (error) => errors.push(error.message))
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text())
  })
  const headers = localApiHeaders()
  const projectResponse = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/`,
    { headers, data: { name: `Evaluation UI ${Date.now()}` } },
  )
  expect(projectResponse.ok()).toBeTruthy()
  const project = await projectResponse.json()
  const imported = await page.request.post(
    `${backendBaseUrl}/api/v1/projects/${project.id}/imports`,
    {
      headers,
      multipart: {
        file: {
          buffer: validCveList,
          mimeType: "text/plain",
          name: "evaluation-ui.txt",
        },
        input_type: "cve-list",
        locked_provider_data: "true",
        provider_snapshot_file: "demo_provider_snapshot.json",
      },
    },
  )
  expect(imported.ok()).toBeTruthy()
  const queued = await imported.json()
  await waitForRunSucceeded(page, queued.id, {
    apiBaseUrl: backendBaseUrl,
    headers,
  })
  const findings = await (
    await page.request.get(
      `${backendBaseUrl}/api/v1/projects/${project.id}/findings/`,
      { headers },
    )
  ).json()
  const finding = findings.data[0]
  await page.goto(`/findings/${finding.id}?projectId=${project.id}`)
  await page.getByRole("button", { name: "Re-evaluate", exact: true }).click()
  await page.getByRole("button", { name: "Start re-evaluation" }).click()
  await expect(
    page.getByText(/Latest project evaluation: (succeeded|completed)/),
  ).toBeVisible({ timeout: 60_000 })
  await page.getByRole("tab", { name: "History", exact: true }).click()
  const history = page.getByRole("region", {
    name: "Decision revisions",
    exact: true,
  })
  await expect(history.locator("article")).toHaveCount(2)
  await expect(page).toHaveTitle("Vuln Prioritizer Workbench")
  await expect(page).toHaveURL(new RegExp(`/findings/${finding.id}`))
  await expect(page.locator("vite-error-overlay")).toHaveCount(0)
  const revisions = await (
    await page.request.get(
      `${backendBaseUrl}/api/v1/findings/${finding.id}/decision-revisions`,
      { headers },
    )
  ).json()
  await mkdir("/tmp/vpw-evaluation-ui", { recursive: true })
  await writeFile(
    "/tmp/vpw-evaluation-ui/native-revisions.json",
    JSON.stringify(revisions, null, 2),
  )
  expect(revisions.data[0].observed_at).toBe(revisions.data[1].observed_at)
  expect(revisions.data[0].is_current).toBe(true)
  expect(revisions.data[0].replay_status).toBe("available")
  await mkdir("/tmp/vpw-evaluation-ui", { recursive: true })
  await page.screenshot({
    path: "/tmp/vpw-evaluation-ui/native-evaluation-desktop.png",
    fullPage: true,
  })
  expect(errors).toEqual([])
})
