import { expect, test } from "@playwright/test"
import { mockFinding, mockProject, routeWorkbenchShell } from "./workbench-route-mocks"

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
