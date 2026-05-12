import AxeBuilder from "@axe-core/playwright"
import { expect, type Page, test } from "@playwright/test"
import { login } from "./auth-helpers"
import { mockFinding, mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

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
    page.getByRole("heading", { level: 1, name: "Risk Operations" }),
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

test("authenticated shell exposes landmarks and account controls", async ({
  page,
}) => {
  await login(page)

  await expect(page.getByRole("main")).toBeVisible()
  await expect(
    page.getByRole("navigation", { name: "Workbench navigation" }),
  ).toBeVisible()
  await expect(page.getByRole("button", { name: "Account menu" })).toBeVisible()
  await expect(
    page
      .getByRole("navigation", { name: "Workbench navigation" })
      .getByRole("link", { exact: true, name: "Findings" }),
  ).toBeVisible()

  await expectNoSeriousA11yViolations(page, "authenticated shell")
  await page.keyboard.press("Tab")
  await expectFocusedElementVisible(page)
})

test("core authenticated routes have no serious accessibility violations", async ({
  page,
}) => {
  test.setTimeout(60_000)
  await login(page)

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

  await page
    .getByRole("button", { name: `Quick view ${mockFinding.cve_id}` })
    .click()
  await expect(
    page.getByRole("dialog", { name: new RegExp(mockFinding.cve_id) }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "findings quick-view sheet")
  await expectDialogVisibleTextContrast(page, "findings quick-view sheet")
  await page.keyboard.press("Escape")

  await page.getByRole("button", { name: "Why now" }).click()
  await expect(
    page.getByRole("dialog", { name: new RegExp(mockFinding.cve_id) }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "findings why dialog", [
    "color-contrast",
  ])
  await expectDialogVisibleTextContrast(page, "findings why dialog")
  await page.keyboard.press("Escape")

  await page.getByRole("link", { name: mockFinding.cve_id }).click()
  await expect(
    page.getByRole("region", { name: "Finding priority decision" }),
  ).toBeVisible()
  await expectNoSeriousA11yViolations(page, "finding detail")
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
