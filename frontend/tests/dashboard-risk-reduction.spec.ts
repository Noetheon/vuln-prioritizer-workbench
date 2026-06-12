import { expect, type Page, test } from "@playwright/test"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

test("dashboard renders risk reduction opportunities across breakpoints", async ({
  page,
}) => {
  const log4jFinding = {
    ...mockFinding,
    asset_key: "payments-api",
    asset_name: "payments-api",
    business_service: "payments",
    component_name: "log4j-core",
    component_purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    component_version: "2.14.1",
    cve_id: "CVE-2021-44228",
    epss: 0.94,
    id: "finding-2",
    owner: "appsec",
    recommended_action: "Upgrade log4j-core.",
    risk_score: 8.7,
    vulnerability_id: "CVE-2021-44228",
  }
  await routeWorkbenchShell(page, {
    findings: [mockFinding, log4jFinding],
    projects: [mockProject],
  })

  for (const viewport of [
    { height: 900, width: 1440 },
    { height: 844, width: 390 },
  ]) {
    await page.setViewportSize(viewport)
    await page.goto(`/?projectId=${mockProject.id}`)

    const panel = page.getByRole("region", { name: "Risk posture" })
    await expect(panel).toBeVisible()
    await expect(panel.getByText("Risk index")).toBeVisible()
    await expect(panel.getByText("Scenario projection")).toBeVisible()
    await expect(panel.getByText("Top risk reducers")).toBeVisible()
    await expect(panel.getByText("projected")).toBeVisible()
    await expect(panel.getByText("target", { exact: true })).toBeVisible()
    await expect(panel.getByText(/governance debt/i)).toBeVisible()
    await expect(
      panel.getByRole("link", { name: /Patch xz|CVE-2024-3094 on xz/ }),
    ).toHaveAttribute("href", /query=CVE-2024-3094/)
    await expect(
      page.getByRole("complementary", { name: "Dashboard context rail" }),
    ).toHaveCount(0)
    await expectNoPageOverflow(page)
  }

  await page.setViewportSize({ height: 900, width: 1440 })
  await page.goto(`/?projectId=${mockProject.id}`)
  await page
    .getByRole("region", { name: "Risk posture" })
    .getByRole("link", { name: /Patch xz|CVE-2024-3094 on xz/ })
    .click()

  await expect(page).toHaveURL(/\/findings\?.*query=CVE-2024-3094/)
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toContainText("CVE-2024-3094")
})

test("dashboard risk reduction shows empty state without actionable risk", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [{ ...mockFinding, risk_score: 0, status: "fixed" }],
    projects: [mockProject],
  })

  await page.goto(`/?projectId=${mockProject.id}`)

  const panel = page.getByRole("region", { name: "Risk posture" })
  await expect(panel).toBeVisible()
  await expect(panel.getByText("No open reduction opportunities")).toBeVisible()
  await expect(
    panel.getByRole("link", { name: "Review findings" }),
  ).toHaveAttribute("href", /\/findings\?projectId=project-1/)
})

async function expectNoPageOverflow(page: Page) {
  const overflow = await page.evaluate(() => ({
    body: document.body.scrollWidth - document.body.clientWidth,
    document:
      document.documentElement.scrollWidth -
      document.documentElement.clientWidth,
  }))
  expect(overflow.document, "document horizontal overflow").toBeLessThanOrEqual(
    1,
  )
  expect(overflow.body, "body horizontal overflow").toBeLessThanOrEqual(1)
}
