import { expect, type Page, test } from "@playwright/test"
import { evidenceScreenshotPath } from "./evidence-paths"
import { mockFinding, mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

async function captureAuditScreenshot(page: Page, fileName: string) {
  await page.screenshot({
    fullPage: true,
    path: evidenceScreenshotPath("ui-productization", "screenshots", fileName),
  })
}

test("findings route renders the empty live queue without demo data", async ({
  page,
}) => {
  await routeWorkbenchShell(page)
  await page.goto("/findings")

  await expect(page.getByText("Demo preview")).toHaveCount(0)
  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()

  await expect(page.getByText("Finding Decisions")).toHaveCount(0)
  await expect(page.getByText("Provider Status")).toHaveCount(0)
  await expect(page.getByText("Evidence Flow")).toHaveCount(0)

  await expect(page.getByText("No projects yet")).toBeVisible()
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toHaveCount(0)

  await expect(
    page.getByRole("combobox", { name: "Sort direction" }),
  ).toHaveCount(0)

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
})

test("finding detail API errors do not fall back to demo findings", async ({
  page,
}) => {
  await routeWorkbenchShell(page)
  await page.route("**/api/v1/findings/demo-f1", (route) =>
    route.fulfill({
      contentType: "application/json",
      status: 404,
      body: JSON.stringify({ detail: "Finding not found" }),
    }),
  )

  await page.goto("/findings/demo-f1")

  await expect(page.getByText("Finding detail unavailable")).toBeVisible()
  await expect(page.getByText("Demo preview")).toHaveCount(0)
  await expect(page.getByText("CVE-2024-3094")).toHaveCount(0)
})

test("findings table owns horizontal scroll without page overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 768, height: 1024 })
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto("/findings")

  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toContainText("CVE-2024-3094")
  const scrollRegion = page.getByRole("region", {
    name: "Findings table scroll region",
  })
  const metrics = await scrollRegion.evaluate((region) => {
    const documentElement = document.documentElement
    region.scrollLeft = region.scrollWidth
    return {
      bodyScrollWidth: document.body.scrollWidth,
      documentScrollWidth: documentElement.scrollWidth,
      regionClientWidth: region.clientWidth,
      regionScrollLeft: region.scrollLeft,
      regionScrollWidth: region.scrollWidth,
      viewportWidth: documentElement.clientWidth,
    }
  })

  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.documentScrollWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.regionClientWidth).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.regionScrollWidth).toBeGreaterThan(metrics.regionClientWidth)
  expect(metrics.regionScrollLeft).toBeGreaterThan(0)
})

test("findings URL search state survives reload and drives API params", async ({
  page,
}) => {
  const requests: URL[] = []
  const findings = Array.from({ length: 12 }, (_, index) => ({
    ...mockFinding,
    cve_id: `CVE-2024-${3100 + index}`,
    id: `finding-${index}`,
    risk_score: 10 - index / 10,
    vulnerability_id: `CVE-2024-${3100 + index}`,
  }))
  await routeWorkbenchShell(page, {
    findings,
    onFindingsRequest: (url) => requests.push(url),
    projects: [mockProject],
  })

  await page.goto(
    "/findings?assetId=asset-1&assetKey=build-host-1&ownerService=payments&priority=critical&status=open&kev=true&exposure=internet-facing&epssMin=0.7&cvssMin=9&sort=score&direction=desc&limit=10&offset=10",
  )

  await expect(page.getByLabel("Owner / Service")).toHaveValue("payments")
  await expect(page.getByRole("combobox", { name: "Priority" })).toContainText(
    "Critical",
  )
  await expect(page.getByRole("combobox", { name: "Status" })).toContainText(
    "Open",
  )
  await expect(page.getByText("build-host-1", { exact: true })).toBeVisible()
  await expect(page.getByLabel("EPSS min")).toHaveValue("0.7")
  await expect(page.getByLabel("CVSS min")).toHaveValue("9")
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toBeVisible()

  await expect.poll(() => requests.at(-1)?.searchParams.get("asset_id")).toBe(
    "asset-1",
  )
  const lastRequest = requests.at(-1)
  expect(lastRequest?.searchParams.get("owner_service")).toBe("payments")
  expect(lastRequest?.searchParams.get("priority")).toBe("critical")
  expect(lastRequest?.searchParams.get("status")).toBe("open")
  expect(lastRequest?.searchParams.get("kev")).toBe("true")
  expect(lastRequest?.searchParams.get("exposure")).toBe("internet-facing")
  expect(lastRequest?.searchParams.get("epss_min")).toBe("0.7")
  expect(lastRequest?.searchParams.get("cvss_min")).toBe("9")
  expect(lastRequest?.searchParams.get("sort")).toBe("score")
  expect(lastRequest?.searchParams.get("direction")).toBe("desc")
  expect(lastRequest?.searchParams.get("limit")).toBe("10")
  expect(lastRequest?.searchParams.get("offset")).toBe("10")

  await page.reload()

  await expect(page.getByLabel("Owner / Service")).toHaveValue("payments")
  await expect(page).toHaveURL(/ownerService=payments/)
  await expect.poll(() => requests.at(-1)?.searchParams.get("offset")).toBe(
    "10",
  )
})

test("findings controls update canonical URLs and preserve detail back context", async ({
  page,
}) => {
  const requests: URL[] = []
  const findings = Array.from({ length: 12 }, (_, index) => ({
    ...mockFinding,
    cve_id: `CVE-2024-${3200 + index}`,
    id: `finding-${index}`,
    risk_score: 10 - index / 10,
    vulnerability_id: `CVE-2024-${3200 + index}`,
  }))
  await routeWorkbenchShell(page, {
    findings,
    onFindingsRequest: (url) => requests.push(url),
    projects: [mockProject],
  })

  await page.goto("/findings?assetId=asset-1&assetKey=build-host-1")
  await page.getByRole("button", { name: "Clear asset filter" }).click()
  await expect(page).not.toHaveURL(/assetId=/)

  await page.getByRole("combobox", { name: "Priority" }).click()
  await page.getByRole("option", { name: "Critical" }).click()
  await expect(page).toHaveURL(/priority=critical/)
  await expect.poll(() => requests.at(-1)?.searchParams.get("priority")).toBe(
    "critical",
  )

  await page.getByRole("button", { name: /Sort by Score/ }).click()
  await expect(page).toHaveURL(/sort=score/)
  await expect(page).toHaveURL(/direction=desc/)
  await expect.poll(() => requests.at(-1)?.searchParams.get("sort")).toBe(
    "score",
  )

  await page.getByRole("button", { name: "Next" }).click()
  await expect(page).toHaveURL(/offset=10/)
  await expect.poll(() => requests.at(-1)?.searchParams.get("offset")).toBe(
    "10",
  )

  await page.getByRole("link", { name: "CVE-2024-3210" }).click()
  await expect(page).toHaveURL(/\/findings\/finding-10\?/)
  await expect(page).toHaveURL(/priority=critical/)
  await page.getByRole("link", { name: "Back to Findings" }).click()
  await expect(page).toHaveURL(/\/findings\?/)
  await expect(page).toHaveURL(/priority=critical/)
  await expect(page).toHaveURL(/sort=score/)
  await expect(page).toHaveURL(/offset=10/)
})

test("findings detail, quick-view sheet, why dialog, and scroll evidence are covered", async ({
  page,
}) => {
  const cvePattern = new RegExp(mockFinding.cve_id)
  await page.setViewportSize({ width: 1440, height: 900 })
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto("/findings?priority=critical&sort=score&direction=desc")

  const scrollRegion = page.getByRole("region", {
    name: "Findings table scroll region",
  })
  await expect(scrollRegion).toBeVisible()
  const scrollMetrics = await scrollRegion.evaluate((region) => {
    region.scrollLeft = region.scrollWidth
    return {
      clientWidth: region.clientWidth,
      scrollLeft: region.scrollLeft,
      scrollWidth: region.scrollWidth,
    }
  })
  expect(scrollMetrics.scrollWidth).toBeGreaterThan(scrollMetrics.clientWidth)
  expect(scrollMetrics.scrollLeft).toBeGreaterThan(0)
  await captureAuditScreenshot(
    page,
    "vpw-aud-204-findings-table-scroll-1440.png",
  )

  await page.getByRole("button", { name: "Why now" }).click()
  const whyDialog = page.getByRole("dialog", { name: cvePattern })
  await expect(whyDialog).toBeVisible()
  await expect(whyDialog).toContainText("Recommended action")
  await expect(whyDialog).toContainText("Patch xz.")
  await captureAuditScreenshot(page, "vpw-aud-204-why-dialog-1440.png")
  await page.keyboard.press("Escape")
  await expect(whyDialog).toHaveCount(0)

  await page
    .getByRole("button", { name: `Quick view ${mockFinding.cve_id}` })
    .click()
  const quickViewSheet = page.getByRole("dialog", { name: cvePattern })
  await expect(quickViewSheet).toBeVisible()
  await expect(quickViewSheet).toContainText("Risk Score")
  await expect(quickViewSheet).toContainText("Open full detail")
  await captureAuditScreenshot(page, "vpw-aud-204-quick-view-sheet-1440.png")

  await quickViewSheet.getByRole("link", { name: "Open full detail" }).click()
  await expect(page).toHaveURL(/\/findings\/finding-1\?/)
  await expect(page).toHaveURL(/priority=critical/)
  await expect(
    page.getByRole("region", { name: "Finding priority decision" }),
  ).toBeVisible()
  await expect(page.getByRole("heading", { name: cvePattern })).toBeVisible()
  await expect(page.getByRole("region", { name: "Risk to decision" })).toBeVisible()

  await page.getByRole("tab", { name: "TTP Context" }).click()
  await expect(
    page.getByRole("region", { name: "TTP context empty state" }),
  ).toBeVisible()

  await page.getByRole("tab", { name: "History" }).click()
  await expect(page.getByRole("region", { name: "Finding history" })).toBeVisible()
  await captureAuditScreenshot(page, "vpw-aud-204-finding-detail-1440.png")

  await page.getByRole("link", { name: "Back to Findings" }).click()
  await expect(page).toHaveURL(/\/findings\?/)
  await expect(page).toHaveURL(/sort=score/)
  await expect(page).toHaveURL(/priority=critical/)
})

test("findings loading and disabled control semantics are observable", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    findingsDelayMs: 500,
    projects: [mockProject],
  })

  await page.goto("/findings")

  const loadingRegion = page.getByRole("status", { name: "Loading findings" })
  await expect(loadingRegion).toBeVisible()
  await expect(loadingRegion).toHaveAttribute("aria-busy", "true")
  await expect(page.locator(".findings-remediation-layout")).toHaveAttribute(
    "aria-busy",
    "true",
  )

  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toBeVisible()
  await expect(page.locator(".findings-remediation-layout")).toHaveAttribute(
    "aria-busy",
    "false",
  )
  await expect(page.getByRole("button", { name: "Reset" })).toBeDisabled()
  await expect(page.getByRole("button", { name: "Previous" })).toBeDisabled()
  await expect(page.getByRole("button", { name: "Next" })).toBeDisabled()
})

test("invalid findings URL params are normalized before API requests", async ({
  page,
}) => {
  const requests: URL[] = []
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    onFindingsRequest: (url) => requests.push(url),
    projects: [mockProject],
  })

  await page.goto(
    "/findings?sort=invalid&direction=sideways&limit=999&offset=-5&priority=urgent&epssMin=nope&cvssMax=42&assetKey=orphan",
  )

  await expect(page).toHaveURL(/\/findings$/)
  await expect.poll(() => requests.at(-1)?.searchParams.get("sort")).toBe(
    "operational",
  )
  const lastRequest = requests.at(-1)
  expect(lastRequest?.searchParams.get("direction")).toBe("asc")
  expect(lastRequest?.searchParams.get("limit")).toBe("10")
  expect(lastRequest?.searchParams.get("offset")).toBe("0")
  expect(lastRequest?.searchParams.has("priority")).toBe(false)
  expect(lastRequest?.searchParams.has("epss_min")).toBe(false)
  expect(lastRequest?.searchParams.has("cvss_max")).toBe(false)
  expect(lastRequest?.searchParams.has("asset_id")).toBe(false)
})
