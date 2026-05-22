import { expect, type Locator, test } from "@playwright/test"
import { evidenceScreenshotPath } from "./evidence-paths"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

async function expectButtonStateTokens(
  button: Locator,
  tokens: { background: string; border: string; text: string },
) {
  const colors = await button.evaluate((element, tokenNames) => {
    const rootStyle = window.getComputedStyle(document.documentElement)
    const buttonStyle = window.getComputedStyle(element)
    const probe = document.createElement("span")
    document.body.append(probe)

    probe.style.backgroundColor = rootStyle
      .getPropertyValue(tokenNames.background)
      .trim()
    const expectedBackground = window.getComputedStyle(probe).backgroundColor

    probe.style.borderTopColor = rootStyle
      .getPropertyValue(tokenNames.border)
      .trim()
    const expectedBorder = window.getComputedStyle(probe).borderTopColor

    probe.style.color = rootStyle.getPropertyValue(tokenNames.text).trim()
    const expectedText = window.getComputedStyle(probe).color

    probe.remove()

    return {
      background: buttonStyle.backgroundColor,
      border: buttonStyle.borderTopColor,
      expectedBackground,
      expectedBorder,
      expectedText,
      text: buttonStyle.color,
    }
  }, tokens)

  expect(colors.background).toBe(colors.expectedBackground)
  expect(colors.border).toBe(colors.expectedBorder)
  expect(colors.text).toBe(colors.expectedText)
}

test("shared controls show distinct default, outline, ghost, icon, and disabled states", async ({
  page,
}) => {
  await page.setViewportSize({ height: 1000, width: 1440 })
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto("/findings")
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toBeVisible()

  await expect(
    page.getByRole("link", { name: /Generate evidence/ }),
  ).toBeVisible()
  await expect(
    page.getByRole("link", { name: /Import findings/ }),
  ).toBeVisible()
  await expect(
    page.getByRole("button", {
      name: new RegExp(`Quick view ${mockFinding.cve_id}`),
    }),
  ).toBeVisible()

  const resetButton = page.getByRole("button", { name: "Reset" })
  await expect(resetButton).toBeDisabled()
  await expectButtonStateTokens(resetButton, {
    background: "--vpw-bg-disabled",
    border: "--vpw-border-disabled",
    text: "--vpw-text-disabled",
  })

  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath(
      "ui-productization",
      "screenshots",
      "vpw-aud-205-button-states-findings-1440.png",
    ),
  })
})

test("shared controls show tokenized busy state separately from disabled", async ({
  page,
}) => {
  await page.setViewportSize({ height: 1000, width: 1440 })
  await routeWorkbenchShell(page, {
    providerStatusDelayMs: 3_000,
    projects: [mockProject],
  })

  await page.goto("/providers")
  const refreshButton = page
    .getByLabel("Provider actions")
    .getByRole("button", { name: "Refresh status" })
  await expect(refreshButton).toBeVisible()
  await expect(refreshButton).toBeDisabled()
  await expect(refreshButton).toHaveAttribute("aria-busy", "true")
  await expectButtonStateTokens(refreshButton, {
    background: "--vpw-bg-busy",
    border: "--vpw-border-busy",
    text: "--vpw-text-busy",
  })

  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath(
      "ui-productization",
      "screenshots",
      "vpw-aud-205-button-busy-providers-1440.png",
    ),
  })
})
