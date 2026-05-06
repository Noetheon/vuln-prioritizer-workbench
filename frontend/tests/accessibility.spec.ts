import AxeBuilder from "@axe-core/playwright"
import { expect, type Page, test } from "@playwright/test"
import { login } from "./auth-helpers"

async function expectFocusedElementVisible(page: Page) {
  await expect(page.locator(":focus")).toBeVisible()
}

async function expectNoSeriousA11yViolations(page: Page, routeName: string) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze()
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

test("login exposes labels, required fields, and keyboard submit", async ({
  page,
}) => {
  await page.goto("/login")

  await expect(page.getByRole("main")).toBeVisible()
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
  await expect(page.getByLabel("Email")).toHaveValue("")
  await expect(page.getByLabel("Password")).toHaveValue("")
  await expect(
    page.evaluate(() => window.localStorage.getItem("access_token")),
  ).resolves.toBeNull()
  await expect(page.getByLabel("Email")).toHaveAttribute("required", "")
  await expect(page.getByLabel("Password")).toHaveAttribute("required", "")

  await page.keyboard.press("Tab")
  await expect(page.getByLabel("Email")).toBeFocused()
  await expectNoSeriousA11yViolations(page, "login")
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

  await page.keyboard.press("Tab")
  await expectFocusedElementVisible(page)
  await expectNoSeriousA11yViolations(page, "authenticated shell")
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
