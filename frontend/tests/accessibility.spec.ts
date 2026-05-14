import AxeBuilder from "@axe-core/playwright"
import { expect, type Page, test } from "@playwright/test"
import type { ProviderStatusPublic } from "../src/api-client"
import { openWorkbench } from "./workbench-runtime-helpers"
import {
  mockAsset,
  mockFinding,
  mockProject,
  mockWaiver,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

const accessibleProviderStatus: ProviderStatusPublic = {
  cache_age_seconds: 600,
  cache_dir: "/var/tmp/vpw/cache",
  last_sync: "2025-04-30T10:00:00Z",
  latest_update_job: {
    execution_mode: "background",
    finished_at: "2025-04-30T10:01:00Z",
    id: "provider-job-accessibility",
    requested_sources: ["nvd", "epss", "kev"],
    started_at: "2025-04-30T10:00:00Z",
    status: "succeeded",
  },
  snapshot: {
    content_hash: "sha256:accessible-provider-snapshot",
    generated_at: "2025-04-30T10:01:00Z",
    id: "snapshot-accessibility",
    locked_provider_data: false,
    missing: false,
    mode: "cache-only",
    requested_cves: 3,
    selected_sources: ["nvd", "epss", "kev"],
  },
  snapshot_dir: "/var/tmp/vpw/snapshots",
  snapshot_mode: "cache-only",
  sources: [
    {
      available: true,
      cache_age_seconds: 600,
      detail: "NVD source available.",
      last_sync: "2025-04-30T10:00:00Z",
      name: "nvd",
      selected: true,
      stale: false,
      value: "2025-04-30",
    },
  ],
  status: "ok",
  warnings: [],
}

async function expectFocusedElementVisible(page: Page) {
  await expect(page.locator(":focus")).toBeVisible()
}

async function expectNoSeriousA11yViolations(
  page: Page,
  routeName: string,
  disabledRules: string[] = [],
) {
  const builder = new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
  for (const rule of disabledRules) {
    builder.disableRules([rule])
  }
  const results = await builder.analyze()
  const seriousOrCritical = results.violations.filter((violation) =>
    ["critical", "serious"].includes(violation.impact ?? ""),
  )
  expect(
    seriousOrCritical,
    `${routeName} has serious/critical accessibility violations: ${seriousOrCritical
      .map((violation) => `${violation.id}: ${violation.help}`)
      .join("; ")}`,
  ).toEqual([])
}

async function expectDialogVisibleTextContrast(page: Page, label: string) {
  const minimumContrast = await page
    .getByRole("dialog")
    .evaluate((dialog) => {
      function rgbParts(value: string) {
        const match = value.match(/rgba?\(([^)]+)\)/)
        if (!match) return null
        const parts = match[1]
          .split(",")
          .slice(0, 3)
          .map((part) => Number.parseFloat(part.trim()))
        return parts.length === 3 && parts.every(Number.isFinite)
          ? parts
          : null
      }

      function luminance([red, green, blue]: number[]) {
        const values = [red, green, blue].map((channel) => {
          const value = channel / 255
          return value <= 0.03928
            ? value / 12.92
            : ((value + 0.055) / 1.055) ** 2.4
        })
        return 0.2126 * values[0] + 0.7152 * values[1] + 0.0722 * values[2]
      }

      function contrast(foreground: number[], background: number[]) {
        const fg = luminance(foreground)
        const bg = luminance(background)
        const lighter = Math.max(fg, bg)
        const darker = Math.min(fg, bg)
        return (lighter + 0.05) / (darker + 0.05)
      }

      function backgroundFor(element: Element) {
        let current: Element | null = element
        while (current) {
          const background = window.getComputedStyle(current).backgroundColor
          if (background && !/rgba?\(0, 0, 0, 0\)/.test(background)) {
            return rgbParts(background)
          }
          current = current.parentElement
        }
        return rgbParts(window.getComputedStyle(document.body).backgroundColor)
      }

      const candidates = Array.from(
        dialog.querySelectorAll("p, span, dt, dd, strong, .vpw-badge"),
      ).filter((element) => {
        const rect = element.getBoundingClientRect()
        return rect.width > 0 && rect.height > 0 && element.textContent?.trim()
      })
      const ratios = candidates
        .map((element) => {
          const foreground = rgbParts(window.getComputedStyle(element).color)
          const background = backgroundFor(element)
          return foreground && background ? contrast(foreground, background) : 0
        })
        .filter((ratio) => Number.isFinite(ratio) && ratio > 0)
      return ratios.length > 0 ? Math.min(...ratios) : 0
    })
  expect(minimumContrast, `${label} computed visible text contrast`).toBeGreaterThanOrEqual(4.5)
}

test("local Workbench opens without credential fields", async ({
  page,
}) => {
  await page.goto("/")

  await expect(page.getByRole("main")).toBeVisible()
  await expect(
    page.getByRole("heading", { level: 1, name: "Overview" }),
  ).toBeVisible()
  await expect(page.getByLabel("Email")).toHaveCount(0)
  await expect(page.getByLabel("Password")).toHaveCount(0)
  await expect(
    page.evaluate(() => window.localStorage.getItem("access_token")),
  ).resolves.toBeNull()

  await page.keyboard.press("Tab")
  await expectFocusedElementVisible(page)
  await expectNoSeriousA11yViolations(page, "local Workbench entry")
})

test("local Workbench entry has no credential failure state", async ({
  page,
}) => {
  await page.goto("/")

  await expect(page.getByRole("alert")).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Sign in" })).toHaveCount(0)
  await expectNoSeriousA11yViolations(page, "local Workbench entry")
})

test("local shell exposes landmarks and workspace controls", async ({
  page,
}) => {
  await openWorkbench(page)

  await expect(page.getByRole("main")).toBeVisible()
  await expect(
    page.getByRole("navigation", { name: "Workbench navigation" }),
  ).toBeVisible()
  await expect(page.getByLabel("Local workspace status")).toBeVisible()
  await expect(
    page
      .getByRole("navigation", { name: "Workbench navigation" })
      .getByRole("link", { exact: true, name: "Triage" }),
  ).toBeVisible()

  await expectNoSeriousA11yViolations(page, "local shell")
  await page.keyboard.press("Tab")
  await expectFocusedElementVisible(page)
})

test("core Workbench routes have no serious accessibility violations", async ({
  page,
}) => {
  test.setTimeout(60_000)
  await openWorkbench(page)

  for (const [path, routeName] of [
    ["/", "dashboard"],
    ["/projects", "projects"],
    ["/imports", "imports"],
    ["/findings", "findings"],
    ["/assets", "assets"],
    ["/reports", "reports"],
    ["/providers", "providers"],
    ["/settings", "settings"],
    ["/waivers", "waivers"],
  ] as const) {
    await page.goto(path)
    await expect(page.getByRole("main")).toBeVisible()
    await expectNoSeriousA11yViolations(page, routeName)
  }
})

test("findings dialogs, detail, and loading states have no serious accessibility violations", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto("/findings")
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toBeVisible()

  const quickViewButton = page.getByRole("button", {
    name: `Quick view ${mockFinding.cve_id}`,
  })
  await quickViewButton.click()
  const quickViewDialog = page.getByRole("dialog", {
    name: new RegExp(mockFinding.cve_id),
  })
  await expect(quickViewDialog).toBeVisible()
  await expect(quickViewDialog.locator(":focus")).toBeVisible()
  await page.keyboard.press("Tab")
  await expect(quickViewDialog.locator(":focus")).toBeVisible()
  await page.keyboard.press("Shift+Tab")
  await expect(quickViewDialog.locator(":focus")).toBeVisible()
  await expect(page.getByText("Defensive ATT&CK context")).toBeVisible()
  await expectNoSeriousA11yViolations(page, "findings quick-view sheet")
  await expectDialogVisibleTextContrast(page, "findings quick-view sheet")
  await page.keyboard.press("Escape")
  await expect(quickViewDialog).toHaveCount(0)
  await expect(quickViewButton).toBeFocused()

  await page
    .getByRole("link", { exact: true, name: mockFinding.cve_id })
    .click()
  await expect(
    page.getByRole("region", { name: "Finding priority decision" }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "finding detail")
})

test("asset drawer modes have no serious accessibility violations", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    assets: [mockAsset],
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto("/assets")
  await page
    .getByRole("table", { name: "Assets table" })
    .locator("tbody tr")
    .filter({ hasText: mockAsset.name })
    .getByRole("button", { exact: true, name: "View" })
    .click()
  await expect(
    page.getByRole("dialog", { name: mockAsset.name }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "asset detail drawer")
  await expectDialogVisibleTextContrast(page, "asset detail drawer")

  await page.getByRole("button", { name: "Linked findings" }).click()
  await expect(
    page.getByRole("dialog", { name: /Linked findings for build-host-1/ }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "asset linked findings drawer")
})

test("risk acceptance drawers have no serious accessibility violations", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
    waivers: [mockWaiver],
  })

  await page.goto("/waivers")
  await page
    .getByRole("table", { name: "Risk acceptance register table" })
    .locator("tbody tr")
    .filter({ hasText: "CVE-2024-3094" })
    .getByRole("button", { exact: true, name: "View" })
    .click()
  await expect(
    page.getByRole("dialog", { name: /CVE-2024-3094/ }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "risk acceptance detail drawer")
  await expectDialogVisibleTextContrast(page, "risk acceptance detail drawer")

  await page.getByRole("button", { name: "Review/edit" }).click()
  await expect(
    page.getByRole("dialog", { name: /Review.*CVE-2024-3094/ }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "risk acceptance review drawer")

  await page.getByRole("button", { name: "Close" }).click()
  await page
    .getByRole("table", { name: "Risk acceptance register table" })
    .locator("tbody tr")
    .filter({ hasText: "CVE-2024-3094" })
    .getByRole("button", { name: "Expire" })
    .click()
  await expect(
    page.getByRole("dialog", { name: /Expire.*CVE-2024-3094/ }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "risk acceptance expire drawer")
})

test("data source tabs have no serious accessibility violations", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    projects: [mockProject],
    providerStatus: accessibleProviderStatus,
  })

  await page.goto("/providers")
  await expect(
    page.getByRole("heading", { level: 1, name: "Data Sources" }),
  ).toBeVisible()

  const sourcesTab = page.getByRole("tab", { name: "Sources" })
  const snapshotTab = page.getByRole("tab", { name: "Snapshot & Cache" })
  const qualityTab = page.getByRole("tab", { name: "Quality Notes" })
  await sourcesTab.focus()
  await expect(sourcesTab).toBeFocused()
  await page.keyboard.press("ArrowRight")
  await expect(snapshotTab).toBeFocused()
  await expect(snapshotTab).toHaveAttribute("aria-selected", "true")
  await page.keyboard.press("End")
  await expect(qualityTab).toBeFocused()
  await expect(qualityTab).toHaveAttribute("aria-selected", "true")
  await page.keyboard.press("Home")
  await expect(sourcesTab).toBeFocused()
  await expect(sourcesTab).toHaveAttribute("aria-selected", "true")

  for (const tabName of [
    "Sources",
    "Snapshot & Cache",
    "Diagnostics",
    "Quality Notes",
  ]) {
    await page.getByRole("tab", { name: tabName }).click()
    await expect(
      page.getByRole("tab", { name: tabName }),
    ).toHaveAttribute("aria-selected", "true")
    await expectNoSeriousA11yViolations(page, `data sources ${tabName} tab`)
  }
})

test("findings busy state has no serious accessibility violations", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    findingsDelayMs: 500,
    projects: [mockProject],
  })

  await page.goto("/findings")
  await expect(
    page.getByRole("status", { name: "Loading findings" }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "findings busy state")
})
