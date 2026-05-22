import { expect, type Page, test } from "@playwright/test"
import { evidenceScreenshotPath } from "./evidence-paths"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

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
  await expect(page.getByLabel("Local workspace status")).toBeVisible()
  await expect(page.getByRole("menuitem", { name: "Sign out" })).toHaveCount(0)
  await page.getByRole("button", { name: "Collapse sidebar" }).click()
  await expect(sidebar).toHaveCSS("width", "72px")
  await expect(
    page.getByRole("button", { name: "Expand sidebar" }),
  ).toBeVisible()
  await expect(
    page
      .getByRole("navigation", { name: "Workbench navigation" })
      .getByText("Overview"),
  ).toHaveCount(0)
})

test("projects route surfaces partial summary failures", async ({ page }) => {
  const secondaryProject = {
    ...mockProject,
    id: "project-2",
    name: "Identity Platform",
  }
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject, secondaryProject],
  })
  await page.route("**/api/v1/projects/project-2/summary", (route) =>
    route.fulfill({
      contentType: "application/json",
      status: 503,
      body: JSON.stringify({ detail: "Summary unavailable" }),
    }),
  )

  await page.goto("/projects")

  await expect(page.getByText("Project summary data incomplete")).toBeVisible()
  await expect(
    page.getByText(/1 project summary could not be loaded/),
  ).toBeVisible()
  await expect(
    page.getByRole("heading", { level: 1, name: "Projects" }),
  ).toBeVisible()
})

test("providers route shows provider failures without placeholder source rows", async ({
  page,
}) => {
  await routeWorkbenchShell(page, { providerStatusError: true })

  await page.goto("/providers")

  await expect(page.getByText("Provider data unavailable")).toBeVisible()
  await expect(
    page.getByRole("table", { name: "Data source inventory" }),
  ).toHaveCount(0)
  await expect(page.getByText("NVD source")).toHaveCount(0)
  await expect(page.getByText("EPSS provider")).toHaveCount(0)
  await expect(page.getByText("KEV provider")).toHaveCount(0)
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

test("malformed finding detail URL fails closed without app crash", async ({
  page,
}) => {
  const pageErrors: Error[] = []
  page.on("pageerror", (error) => pageErrors.push(error))
  await routeWorkbenchShell(page)

  await page.goto("/findings")
  await page.evaluate(() => {
    window.history.pushState({}, "", "/findings/%E0%A4%A")
    window.dispatchEvent(new PopStateEvent("popstate"))
  })

  await expect(page.getByText("Route not found")).toBeVisible()
  expect(pageErrors).toEqual([])
})

test("workbench shell renders when localStorage access is blocked", async ({
  page,
}) => {
  await page.addInitScript(() => {
    const blocked = () => {
      throw new DOMException("localStorage blocked", "SecurityError")
    }
    Storage.prototype.getItem = blocked
    Storage.prototype.setItem = blocked
  })
  await routeWorkbenchShell(page)

  await page.goto("/findings")

  await expect(
    page.getByRole("region", { name: "Findings filters" }),
  ).toBeVisible()
  await expect(page.getByLabel("Local workspace status")).toBeVisible()
})

test("finding detail still renders when optional explanation fails", async ({
  page,
}) => {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })
  await page.route("**/api/v1/findings/finding-1/explain", (route) =>
    route.fulfill({
      contentType: "application/json",
      status: 500,
      body: JSON.stringify({ detail: "Explanation provider unavailable" }),
    }),
  )

  await page.goto("/findings/finding-1")

  await expect(page.getByText("Priority explanation unavailable")).toBeVisible()
  await expect(
    page.getByRole("heading", { name: /CVE-2024-3094/ }),
  ).toBeVisible()
  await expect(
    page.getByRole("region", { name: "Finding priority decision" }),
  ).toBeVisible()
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

  expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(metrics.viewportWidth + 1)
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
    "/findings?projectId=project-1&assetId=asset-1&assetKey=build-host-1&ownerService=payments&priority=critical&status=open&kev=true&exposure=internet-facing&epssMin=0.7&cvssMin=9&sort=score&direction=desc&limit=10&offset=10",
  )

  await expect(page.getByLabel("Owner / Service")).toHaveValue("payments")
  await expect(page.getByRole("combobox", { name: "Priority" })).toContainText(
    "Critical",
  )
  await expect(page.getByRole("combobox", { name: "Status" })).toContainText(
    "Open",
  )
  await expect(
    page
      .getByRole("region", { name: "Findings filters" })
      .getByText("build-host-1", { exact: true }),
  ).toBeVisible()
  await expect(page.getByLabel("EPSS min")).toHaveValue("0.7")
  await expect(page.getByLabel("CVSS min")).toHaveValue("9")
  await expect(
    page.getByRole("table", { name: "Findings remediation queue" }),
  ).toBeVisible()

  await expect
    .poll(() => requests.at(-1)?.searchParams.get("asset_id"))
    .toBe("asset-1")
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
  for (const pattern of [
    /projectId=project-1/,
    /assetId=asset-1/,
    /kev=true/,
    /epssMin=0\.7/,
    /cvssMin=9/,
    /sort=score/,
    /direction=desc/,
    /offset=10/,
  ]) {
    await expect(page).toHaveURL(pattern)
  }
  await expect(page).toHaveURL(/ownerService=payments/)
  await expect
    .poll(() => requests.at(-1)?.searchParams.get("offset"))
    .toBe("10")
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

  await page.getByLabel("Owner / Service").fill("payments")
  await expect(page.getByLabel("Owner / Service")).toHaveValue("payments")
  await expect(page).toHaveURL(/ownerService=payments/)
  await expect
    .poll(() => requests.at(-1)?.searchParams.get("owner_service"))
    .toBe("payments")

  await page.getByRole("combobox", { name: "Priority" }).click()
  await page.getByRole("option", { name: "Critical" }).click()
  await expect(page).toHaveURL(/priority=critical/)
  await expect
    .poll(() => requests.at(-1)?.searchParams.get("priority"))
    .toBe("critical")
  const signalsButton = page.getByRole("button", {
    name: /^Signals(?:\s+\d+)?$/,
  })
  await expect(signalsButton).toHaveAttribute("aria-expanded", "false")
  await expect(page.getByRole("combobox", { name: "KEV" })).toHaveCount(0)
  await signalsButton.click()
  await expect(signalsButton).toHaveAttribute("aria-expanded", "true")
  await expect(page.getByRole("combobox", { name: "KEV" })).toBeVisible()
  await expect(page.getByRole("combobox", { name: "Exposure" })).toBeVisible()
  await expect(page.getByLabel("EPSS min")).toBeVisible()
  await expect(page.getByLabel("EPSS max")).toBeVisible()
  await expect(page.getByLabel("CVSS min")).toBeVisible()
  await expect(page.getByLabel("CVSS max")).toBeVisible()
  await page.getByRole("combobox", { name: "KEV" }).click()
  await page.getByRole("option", { exact: true, name: "KEV" }).click()
  await expect(page).toHaveURL(/kev=true/)
  await expect.poll(() => requests.at(-1)?.searchParams.get("kev")).toBe("true")
  await page.reload()
  await expect(signalsButton).toHaveAttribute("aria-expanded", "true")
  await expect(page.getByRole("combobox", { name: "KEV" })).toBeVisible()

  await page.getByRole("button", { name: /Sort by Score/ }).click()
  await expect(page).toHaveURL(/sort=score/)
  await expect(page).toHaveURL(/direction=desc/)
  await expect
    .poll(() => requests.at(-1)?.searchParams.get("sort"))
    .toBe("score")

  await page.getByRole("button", { name: "Next" }).click()
  await expect(page).toHaveURL(/offset=10/)
  await expect
    .poll(() => requests.at(-1)?.searchParams.get("offset"))
    .toBe("10")

  await page.getByRole("link", { exact: true, name: "CVE-2024-3210" }).click()
  await expect(page).toHaveURL(/\/findings\/finding-10\?/)
  await expect(page).toHaveURL(/priority=critical/)
  await page.getByRole("link", { name: "Back to Triage" }).click()
  await expect(page).toHaveURL(/\/findings\?/)
  await expect(page).toHaveURL(/priority=critical/)
  await expect(page).toHaveURL(/sort=score/)
  await expect(page).toHaveURL(/offset=10/)
})

test("findings detail, drawer preview, and scroll evidence are covered", async ({
  page,
}) => {
  const cvePattern = new RegExp(mockFinding.cve_id)
  await page.setViewportSize({ width: 1440, height: 900 })
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })
  await page.route("**/api/v1/findings/finding-1/explain", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        cve_id: mockFinding.cve_id,
        decision_explanation: {
          human_readable:
            "Critical because KEV is listed, EPSS is high, CVSS is critical, and production context increases operational urgency.",
          reasons: [
            {
              code: "priority.kev.known_exploited",
              message: "CISA KEV listed for this CVE.",
            },
            {
              code: "priority.critical.epss_cvss",
              message: "EPSS and CVSS exceed critical thresholds.",
            },
            {
              code: "asset.context",
              message:
                "Asset context marks this as internet-facing production scope.",
            },
          ],
        },
        finding_id: mockFinding.id,
        priority: mockFinding.priority,
        priority_rank: 0,
        project_id: mockFinding.project_id,
        provider_evidence: {
          cvss: mockFinding.cvss_base_score,
          epss: mockFinding.epss,
          kev: mockFinding.in_kev,
        },
        rationale: mockFinding.rationale,
        recommended_action: mockFinding.recommended_action,
        risk_score: mockFinding.risk_score,
      }),
    }),
  )

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
  expect(scrollMetrics.scrollWidth).toBeLessThanOrEqual(
    scrollMetrics.clientWidth + 2,
  )
  expect(scrollMetrics.scrollLeft).toBeLessThanOrEqual(1)
  await captureAuditScreenshot(
    page,
    "vpw-aud-204-findings-table-scroll-1440.png",
  )

  const quickViewButton = page.getByRole("button", {
    name: new RegExp(`Quick view ${mockFinding.cve_id}`),
  })
  await page
    .getByRole("button", {
      name: new RegExp(`Quick view ${mockFinding.cve_id}`),
    })
    .click()
  const quickViewSheet = page.getByRole("dialog", { name: cvePattern })
  await expect(quickViewSheet).toBeVisible()
  await expect(quickViewSheet).toContainText("Recommended action")
  await expect(quickViewSheet).toContainText(
    "Critical because KEV is listed, EPSS is high, CVSS is critical, and production context increases operational urgency.",
  )
  await expect(quickViewSheet).toContainText("Patch xz.")
  await expect(quickViewSheet).toContainText("Evidence snapshot")
  await expect(quickViewSheet).toContainText("generic-occurrence-csv")
  await expect(quickViewSheet).toContainText("Defensive ATT&CK context")
  await expect(quickViewSheet).toContainText("does not prove compromise")
  await expect(quickViewSheet).not.toContainText("No KEV")
  await expect(quickViewSheet).toContainText("Open full detail")
  const fullDetailLink = quickViewSheet.getByRole("link", {
    name: "Open full detail",
  })
  await expect(fullDetailLink).toHaveAttribute(
    "href",
    /\/findings\/finding-1\?.*priority=critical/,
  )
  await expect(fullDetailLink).toHaveAttribute("href", /sort=score/)
  await expect(fullDetailLink).toHaveAttribute("href", /direction=desc/)
  await captureAuditScreenshot(page, "vpw-aud-204-quick-view-sheet-1440.png")
  await quickViewSheet.getByRole("button", { name: "Close" }).first().click()
  await expect(quickViewSheet).toHaveCount(0)
  await expect(quickViewButton).toBeFocused()

  await quickViewButton.click()
  await page
    .getByRole("dialog", { name: cvePattern })
    .getByRole("link", { name: "Open full detail" })
    .click()
  await expect(page).toHaveURL(/\/findings\/finding-1\?/)
  await expect(page).toHaveURL(/priority=critical/)
  await expect(
    page.getByRole("region", { name: "Finding priority decision" }),
  ).toBeVisible()
  await expect(page.getByRole("heading", { name: cvePattern })).toBeVisible()
  await expect(
    page.getByRole("region", { name: "Risk to decision" }),
  ).toBeVisible()
  await expect(
    page.getByRole("complementary", { name: "Triage summary" }),
  ).toContainText("Open in Triage")
  await expect(
    page.getByRole("button", { name: "Refresh evidence" }),
  ).toHaveCount(1)
  await expect(page.getByRole("tab", { name: "Decision" })).toBeVisible()
  await expect(page.getByRole("tab", { name: "Evidence" })).toBeVisible()
  await expect(page.getByRole("tab", { name: "Occurrences" })).toBeVisible()
  await expect(page.getByRole("tab", { name: "Governance" })).toBeVisible()
  await expect(page.getByText("Provider decision audit trail")).toBeVisible()
  await expect(
    page.getByRole("table", { name: "Provider rationale statements" }),
  ).toHaveCount(0)
  await page.getByText("Provider decision audit trail").click()
  await expect(
    page.getByRole("table", { name: "Provider rationale statements" }),
  ).toBeVisible()
  await page.getByText("Provider decision audit trail").click()
  await expect(
    page.getByRole("table", { name: "Provider rationale statements" }),
  ).toHaveCount(0)

  await page.getByRole("tab", { name: "Evidence" }).click()
  await expect(page.getByRole("tabpanel", { name: "Evidence" })).toContainText(
    "Evidence used for this decision",
  )

  await page.getByRole("tab", { name: "Occurrences" }).click()
  const occurrencesPanel = page.getByRole("tabpanel", { name: "Occurrences" })
  await expect(occurrencesPanel).toContainText("Package / PURL")
  await expect(occurrencesPanel).toContainText("Environment")

  await page.getByRole("tab", { name: "ATT&CK" }).click()
  await expect(
    page.getByRole("region", { name: "Threat informed context" }),
  ).toBeVisible()
  await expect(page.getByText("Does not override base priority")).toBeVisible()
  await expect(page.getByText("does not prove exploitation")).toBeVisible()

  await page.getByRole("tab", { name: "History" }).click()
  await expect(
    page.getByRole("region", { name: "Finding history" }),
  ).toBeVisible()

  await page.getByRole("tab", { name: "Governance" }).click()
  const governancePanel = page.getByRole("tabpanel", { name: "Governance" })
  await expect(governancePanel).toContainText("No accepted risk record exists")
  await expect(
    governancePanel.getByRole("link", { name: "Risk acceptance" }),
  ).toBeVisible()
  await captureAuditScreenshot(page, "vpw-aud-204-finding-detail-1440.png")

  await page.getByRole("link", { name: "Back to Triage" }).click()
  await expect(page).toHaveURL(/\/findings\?/)
  await expect(page).toHaveURL(/sort=score/)
  await expect(page).toHaveURL(/priority=critical/)
})

test("finding detail remains scrollable from shell surfaces at MacBook viewport", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1470, height: 956 })
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })

  await page.goto(`/findings/${mockFinding.id}?projectId=${mockProject.id}`)

  const content = page.getByRole("region", {
    name: "Workbench page content",
  })
  await expect(content).toBeVisible()
  await expect(
    page.getByRole("heading", { name: mockFinding.cve_id }),
  ).toBeVisible()

  const initialMetrics = await content.evaluate((element) => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
    scrollTop: element.scrollTop,
  }))
  expect(initialMetrics.scrollHeight).toBeGreaterThan(
    initialMetrics.clientHeight,
  )
  expect(initialMetrics.scrollTop).toBe(0)

  async function expectWheelScrollsToBottomFrom(point: {
    x: number
    y: number
  }) {
    await content.evaluate((element) => {
      element.scrollTop = 0
    })
    await page.mouse.move(point.x, point.y)
    for (let step = 0; step < 14; step += 1) {
      await page.mouse.wheel(0, 900)
    }
    await expect
      .poll(() =>
        content.evaluate(
          (element) =>
            element.scrollTop + element.clientHeight >=
            element.scrollHeight - 4,
        ),
      )
      .toBe(true)

    const metrics = await content.evaluate((element) => ({
      bottomGap:
        element.scrollHeight - element.scrollTop - element.clientHeight,
      clientHeight: element.clientHeight,
      scrollHeight: element.scrollHeight,
      scrollTop: element.scrollTop,
    }))
    expect(metrics.scrollTop).toBeGreaterThan(0)
    expect(metrics.bottomGap).toBeLessThanOrEqual(4)
  }

  await expectWheelScrollsToBottomFrom({ x: 260, y: 112 })
  await expectWheelScrollsToBottomFrom({ x: 760, y: 520 })
  await expect(
    page.getByRole("complementary", { name: "Triage summary" }),
  ).toContainText("Risk acceptance")
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

  await expect(page).toHaveURL(/\/findings(?:\?.*)?$/)
  await expect
    .poll(() => requests.at(-1)?.searchParams.get("sort"))
    .toBe("operational")
  const lastRequest = requests.at(-1)
  expect(lastRequest?.searchParams.get("direction")).toBe("asc")
  expect(lastRequest?.searchParams.get("limit")).toBe("10")
  expect(lastRequest?.searchParams.get("offset")).toBe("0")
  expect(lastRequest?.searchParams.has("priority")).toBe(false)
  expect(lastRequest?.searchParams.has("epss_min")).toBe(false)
  expect(lastRequest?.searchParams.has("cvss_max")).toBe(false)
  expect(lastRequest?.searchParams.has("asset_id")).toBe(false)
})
