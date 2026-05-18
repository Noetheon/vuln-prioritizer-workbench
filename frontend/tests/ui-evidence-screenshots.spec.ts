import { writeFileSync } from "node:fs"
import {
  expect,
  type Page,
  type Route as PlaywrightRoute,
  test,
} from "@playwright/test"
import { evidenceScreenshotPath } from "./evidence-paths"
import {
  mockFinding,
  mockProject,
  routeWorkbenchShell,
} from "./workbench-route-mocks"

type Theme = "light" | "dark"

type EvidenceViewport = {
  height: number
  label: "desktop-1440" | "mobile-390" | "tablet-768"
  width: number
}

type EvidenceRoute = {
  assertReady: (page: Page) => Promise<void>
  id: string
  path: string
}

const themes: readonly Theme[] = ["light", "dark"]

const desktopViewport: EvidenceViewport = {
  height: 1000,
  label: "desktop-1440",
  width: 1440,
}
const mobileViewport: EvidenceViewport = {
  height: 844,
  label: "mobile-390",
  width: 390,
}
const tabletViewport: EvidenceViewport = {
  height: 1024,
  label: "tablet-768",
  width: 768,
}
const evidenceViewports = [
  desktopViewport,
  mobileViewport,
  tabletViewport,
] as const

const timestamp = "2026-05-10T10:00:00Z"
const runId = "run-1"

const evidenceFindings = [
  mockFinding,
  {
    ...mockFinding,
    asset_id: "asset-2",
    asset_key: "checkout-api-1",
    asset_name: "checkout-api-1",
    business_service: "checkout",
    component_name: "log4j-core",
    component_purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    component_version: "2.14.1",
    cve_id: "CVE-2021-44228",
    cvss_base_score: 10,
    epss: 0.88,
    exposure: "internal",
    id: "finding-2",
    in_kev: true,
    owner: "appsec",
    priority: "high",
    rationale: "Remote code execution in a high-value service dependency.",
    recommended_action: "Upgrade log4j-core to a supported release.",
    risk_score: 8.9,
    status: "in_review",
    vulnerability_id: "CVE-2021-44228",
  },
  {
    ...mockFinding,
    asset_id: "asset-3",
    asset_key: "identity-worker-1",
    asset_name: "identity-worker-1",
    business_service: "identity",
    component_name: "openssl",
    component_purl: "pkg:deb/debian/openssl@3.0.11-1",
    component_version: "3.0.11",
    cve_id: "CVE-2023-5363",
    cvss_base_score: 7.5,
    epss: 0.31,
    exposure: "private",
    id: "finding-3",
    in_kev: false,
    owner: "identity",
    priority: "medium",
    rationale: "Cryptography library issue on a private worker tier.",
    recommended_action: "Update OpenSSL during the next maintenance window.",
    risk_score: 5.8,
    status: "open",
    vulnerability_id: "CVE-2023-5363",
  },
]

const evidenceAssets = [
  {
    asset_key: "build-host-1",
    business_service: "payments",
    created_at: timestamp,
    criticality: "critical",
    environment: "production",
    exposure: "internet-facing",
    finding_count: 1,
    id: "asset-1",
    name: "build-host-1",
    owner: "platform",
    project_id: mockProject.id,
    rescore_needed: false,
    target_ref: "pkg:apk/alpine/xz@5.6.0-r0",
    updated_at: timestamp,
  },
  {
    asset_key: "checkout-api-1",
    business_service: "checkout",
    created_at: timestamp,
    criticality: "high",
    environment: "production",
    exposure: "internal",
    finding_count: 1,
    id: "asset-2",
    name: "checkout-api-1",
    owner: "appsec",
    project_id: mockProject.id,
    rescore_needed: false,
    target_ref: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    updated_at: timestamp,
  },
  {
    asset_key: "identity-worker-1",
    business_service: "identity",
    created_at: timestamp,
    criticality: "medium",
    environment: "staging",
    exposure: "private",
    finding_count: 1,
    id: "asset-3",
    name: "identity-worker-1",
    owner: "identity",
    project_id: mockProject.id,
    rescore_needed: true,
    target_ref: "pkg:deb/debian/openssl@3.0.11-1",
    updated_at: timestamp,
  },
]

const evidenceProjectSummary = {
  counts_by_priority: { critical: 1, high: 1, medium: 1 },
  counts_by_status: { in_review: 1, open: 2 },
  cvss_known_count: 3,
  epss_hits: 3,
  finding_count: 3,
  kev_hits: 2,
  latest_run_id: runId,
  latest_run_status: "succeeded",
  latest_run_summary: {
    filename: "vpw-evidence-fixture.txt",
    finding_count: 3,
  },
  open_finding_count: 2,
  project_id: mockProject.id,
  provider_degraded: false,
}

const evidenceRun = {
  filename: "vpw-evidence-fixture.txt",
  finished_at: timestamp,
  id: runId,
  input_type: "cve_list",
  project_id: mockProject.id,
  provider_snapshot_id: "demo",
  started_at: "2026-05-10T09:55:00Z",
  status: "succeeded",
  summary_json: {
    input_upload: { filename: "vpw-evidence-fixture.txt" },
  },
}

const evidenceRunSummary = {
  analysis_decision_scope: "project",
  counts_by_priority: { critical: 1, high: 1, medium: 1 },
  created_findings: 3,
  filename: "vpw-evidence-fixture.txt",
  finding_count: 3,
  finished_at: timestamp,
  id: runId,
  input_type: "cve_list",
  kev_hits: 2,
  occurrence_count: 3,
  parse_errors: [],
  persistence_scope: "project",
  project_id: mockProject.id,
  provider_degraded: false,
  provider_snapshot_id: "demo",
  started_at: "2026-05-10T09:55:00Z",
  status: "succeeded",
  summary_json: {
    evidence_bundle: "ready",
    input_upload: { filename: "vpw-evidence-fixture.txt" },
  },
  updated_findings: 0,
}

const evidenceReport = {
  analysis_run_id: runId,
  content_type: "text/html",
  created_at: timestamp,
  download_url: "/api/v1/reports/report-1/download",
  filename: "vpw-evidence-center.html",
  format: "html",
  id: "report-1",
  kind: "evidence",
  metadata_json: {
    manifest: {
      generated_at: timestamp,
      project: mockProject.name,
    },
  },
  project_id: mockProject.id,
  sha256: "a".repeat(64),
  size_bytes: 64211,
}

const evidenceGovernance = {
  assets: [
    {
      critical_count: 1,
      dimension: "asset",
      finding_count: 1,
      highest_priority: "critical",
      label: "build-host-1",
      open_count: 1,
      risk_score_total: 9.8,
    },
  ],
  environments: [
    {
      critical_count: 1,
      dimension: "environment",
      finding_count: 2,
      highest_priority: "critical",
      label: "production",
      open_count: 1,
      risk_score_total: 18.7,
    },
  ],
  generated_at: timestamp,
  owners: [
    {
      critical_count: 1,
      dimension: "owner",
      finding_count: 1,
      highest_priority: "critical",
      label: "platform",
      open_count: 1,
      risk_score_total: 9.8,
    },
  ],
  project_id: mockProject.id,
  services: [
    {
      critical_count: 1,
      dimension: "service",
      finding_count: 1,
      highest_priority: "critical",
      label: "payments",
      open_count: 1,
      risk_score_total: 9.8,
    },
  ],
  top_assets_by_risk: [
    {
      critical_count: 1,
      dimension: "asset",
      finding_count: 1,
      highest_priority: "critical",
      label: "build-host-1",
      open_count: 1,
      risk_score_total: 9.8,
    },
  ],
  top_services_by_risk: [
    {
      critical_count: 1,
      dimension: "service",
      finding_count: 1,
      highest_priority: "critical",
      label: "payments",
      open_count: 1,
      risk_score_total: 9.8,
    },
    {
      dimension: "service",
      finding_count: 1,
      high_count: 1,
      highest_priority: "high",
      label: "checkout",
      open_count: 0,
      risk_score_total: 8.9,
    },
  ],
  waiver_debt: {
    accepted_finding_count: 1,
    active_count: 1,
    expired_count: 0,
    expiring_soon_count: 1,
    items: [
      {
        asset_key: "build-host-1",
        cve_id: mockFinding.cve_id,
        days_remaining: 36,
        expires_at: "2026-06-15T00:00:00Z",
        finding_id: mockFinding.id,
        id: "waiver-1",
        matched_findings: 1,
        owner: "platform",
        review_at: "2026-05-20T00:00:00Z",
        scope: "finding",
        service: "payments",
        status: "active",
      },
    ],
    matched_finding_count: 1,
    owner_counts: { platform: 1 },
    review_due_count: 0,
    service_counts: { payments: 1 },
    waiver_count: 1,
  },
}

const evidenceWaivers = [
  {
    approval_ref: "CAB-2026-014",
    asset_id: "asset-1",
    asset_key: "build-host-1",
    created_at: timestamp,
    cve_id: mockFinding.cve_id,
    days_remaining: 36,
    expires_at: "2026-06-15T00:00:00Z",
    finding_id: mockFinding.id,
    id: "waiver-1",
    matched_findings: 1,
    owner: "platform",
    project_id: mockProject.id,
    reason:
      "Temporary accepted risk while emergency patch validation completes.",
    review_at: "2026-05-20T00:00:00Z",
    service: "payments",
    status: "active",
    ticket_url: "https://tickets.example/vpw-014",
    updated_at: timestamp,
  },
]

const evidenceProviderStatus = {
  cache_age_seconds: 120,
  last_sync: timestamp,
  snapshot: {
    id: "demo",
    missing: false,
    mode: "demo",
    selected_sources: ["epss", "kev", "vulnrichment"],
  },
  snapshot_mode: "demo",
  sources: [
    {
      available: true,
      cache_age_seconds: 120,
      detail: "EPSS probabilities loaded from locked evidence fixture.",
      last_sync: timestamp,
      name: "FIRST EPSS",
      selected: true,
      stale: false,
      value: "epss",
    },
    {
      available: true,
      cache_age_seconds: 120,
      detail: "Known exploited vulnerability catalog available.",
      last_sync: timestamp,
      name: "CISA KEV",
      selected: true,
      stale: false,
      value: "kev",
    },
    {
      available: true,
      cache_age_seconds: 120,
      detail: "Supplemental vulnerability enrichment available.",
      last_sync: timestamp,
      name: "Vulnrichment",
      selected: true,
      stale: false,
      value: "vulnrichment",
    },
  ],
  status: "ok",
  warnings: [],
}

const entryRoute: EvidenceRoute = {
  assertReady: async (page) => {
    await expect(
      page.getByRole("heading", { level: 1, name: "Overview" }),
    ).toBeVisible({ timeout: 15_000 })
    await expect(page.getByLabel("Email")).toHaveCount(0)
    await expect(page.getByLabel("Password")).toHaveCount(0)
  },
  id: "workbench-entry",
  path: "/",
}

const workbenchRoutes: readonly EvidenceRoute[] = [
  {
    assertReady: async (page) => {
      await expect(
        page
          .getByRole("heading", { level: 1, name: "Overview" })
          .first(),
      ).toBeVisible({ timeout: 15_000 })
      await expect(
        page.getByRole("region", { name: "Risk Operations dashboard" }),
      ).toBeVisible()
    },
    id: "dashboard",
    path: "/",
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Projects" }),
      ).toBeVisible({ timeout: 15_000 })
      await expect(
        page.getByRole("heading", { name: mockProject.name }).first(),
      ).toBeVisible()
    },
    id: "projects",
    path: "/projects",
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Imports" }),
      ).toBeVisible({ timeout: 15_000 })
      await expect(page.getByRole("link", { name: /New import/ })).toBeVisible()
      await expect(page.getByLabel("Evidence file")).toHaveCount(0)
    },
    id: "imports",
    path: "/imports",
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("region", { name: "Findings filters" }),
      ).toBeVisible({ timeout: 15_000 })
      if ((page.viewportSize()?.width ?? desktopViewport.width) < 640) {
        await expect(
          page.getByRole("region", { name: "Findings remediation cards" }),
        ).toContainText(mockFinding.cve_id)
        return
      }

      await expect(
        page.getByRole("table", { name: "Findings remediation queue" }),
      ).toContainText(mockFinding.cve_id)
    },
    id: "findings",
    path: "/findings",
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("heading", { name: new RegExp(mockFinding.cve_id) }),
      ).toBeVisible({ timeout: 15_000 })
      await expect(
        page.getByText(
          "Critical priority combines CISA KEV, 92% EPSS, CVSS 10.0, and Internet Facing exposure.",
        ),
      ).toBeVisible()
      await expect(
        page.getByText(mockFinding.rationale, { exact: true }).first(),
      ).toBeVisible()
      await expect(
        page.getByRole("region", { name: "Finding priority decision" }),
      ).toBeVisible()
    },
    id: "finding-detail",
    path: `/findings/${mockFinding.id}`,
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("heading", { level: 2, name: "Evidence Center" }),
      ).toBeVisible({ timeout: 15_000 })
      await expect(
        page.getByRole("tab", { name: "Artifacts" }),
      ).toHaveAttribute("aria-selected", "true")
      await expect(
        page.getByRole("heading", { name: "Generate Evidence Artifacts" }),
      ).toBeVisible()
    },
    id: "reports-evidence-center",
    path: "/reports",
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("heading", { level: 2, name: "Assets" }).first(),
      ).toBeVisible({ timeout: 15_000 })
      await expect(
        page.getByRole("table", { name: "Assets table" }),
      ).toContainText("build-host-1")
      await expect(
        page.getByRole("button", { name: "Add asset" }),
      ).toBeVisible()
    },
    id: "assets",
    path: "/assets",
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("heading", {
          exact: true,
          level: 2,
          name: "Risk Acceptance",
        }),
      ).toBeVisible({ timeout: 15_000 })
      await expect(page.getByText("CAB-2026-014").first()).toBeVisible()
    },
    id: "waivers",
    path: "/waivers",
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("heading", { level: 1, name: "Data Sources" }),
      ).toBeVisible({ timeout: 15_000 })
      await expect(
        page.getByRole("heading", { level: 2, name: "Data source inventory" }),
      ).toBeVisible()
    },
    id: "providers",
    path: "/providers",
  },
  {
    assertReady: async (page) => {
      await expect(
        page.getByRole("heading", { level: 2, name: "Workspace controls" }),
      ).toBeVisible({ timeout: 15_000 })
      await expect(page.getByRole("tab", { name: "Overview" })).toBeVisible()
      await expect(
        page.getByRole("heading", { name: "Workspace access" }),
      ).toBeVisible()
      await expect(
        page.getByRole("heading", { name: "Account " + "and session" }),
      ).toHaveCount(0)
      await expect(page.getByRole("tab", { name: "API " + "Tokens" })).toHaveCount(0)
      await expect(
        page.getByRole("tab", { name: "Runtime & Providers" }),
      ).toBeVisible()
    },
    id: "settings",
    path: "/settings",
  },
]

const legacyScreenshotAliases = new Map<string, readonly string[]>([
  [
    aliasKey("dashboard", "dark", "desktop-1440"),
    ["ui-31-dashboard-dark-1440.png"],
  ],
  [
    aliasKey("findings", "dark", "desktop-1440"),
    ["ui-31-findings-dark-1440.png"],
  ],
  [
    aliasKey("imports", "dark", "desktop-1440"),
    ["ui-31-imports-dark-1440.png"],
  ],
  [
    aliasKey("reports-evidence-center", "dark", "desktop-1440"),
    ["ui-31-evidence-center-dark-1440.png"],
  ],
  [aliasKey("assets", "dark", "desktop-1440"), ["ui-31-assets-dark-1440.png"]],
  [
    aliasKey("dashboard", "light", "mobile-390"),
    ["ui-32-dashboard-mobile-390.png"],
  ],
  [
    aliasKey("findings", "light", "mobile-390"),
    ["ui-32-findings-mobile-390.png"],
  ],
  [
    aliasKey("imports", "light", "mobile-390"),
    ["ui-32-imports-mobile-390.png"],
  ],
  [
    aliasKey("reports-evidence-center", "light", "mobile-390"),
    ["ui-32-evidence-center-mobile-390.png"],
  ],
  [
    aliasKey("assets", "light", "desktop-1440"),
    ["ui-32-assets-desktop-1440.png"],
  ],
  [aliasKey("assets", "light", "tablet-768"), ["ui-32-assets-tablet-768.png"]],
  [aliasKey("assets", "light", "mobile-390"), ["ui-32-assets-mobile-390.png"]],
  [
    aliasKey("dashboard", "light", "desktop-1440"),
    ["vpw-aud-206-dashboard-1440.png"],
  ],
  [
    aliasKey("findings", "light", "desktop-1440"),
    ["vpw-aud-206-findings-1440.png"],
  ],
  [
    aliasKey("imports", "light", "desktop-1440"),
    ["vpw-aud-206-imports-1440.png"],
  ],
  [
    aliasKey("reports-evidence-center", "light", "desktop-1440"),
    ["vpw-aud-206-reports-1440.png"],
  ],
])

async function fulfillJson(
  route: PlaywrightRoute,
  body: unknown,
  status = 200,
) {
  await route.fulfill({
    body: JSON.stringify(body),
    contentType: "application/json",
    status,
  })
}

function aliasKey(
  routeId: string,
  theme: Theme,
  viewportLabel: EvidenceViewport["label"],
) {
  return `${routeId}:${theme}:${viewportLabel}`
}

function explicitScreenshotName(
  routeId: string,
  theme: Theme,
  viewportLabel: EvidenceViewport["label"],
) {
  return `ui-evidence-${routeId}-${theme}-${viewportLabel}.png`
}

async function assertEvidenceLayout({
  page,
  route,
  theme,
  viewport,
}: {
  page: Page
  route: EvidenceRoute
  theme: Theme
  viewport: EvidenceViewport
}) {
  const metrics = await page.evaluate(() => {
    const documentElement = document.documentElement
    const clippedControls = [
      ...document.querySelectorAll(
        'button, a, [role="button"], [role="combobox"], textarea, select',
      ),
    ]
      .map((element) => {
        const rect = element.getBoundingClientRect()
        const style = getComputedStyle(element)
        const text = (
          element.textContent ??
          element.getAttribute("aria-label") ??
          element.getAttribute("placeholder") ??
          ""
        )
          .replace(/\s+/g, " ")
          .trim()
        const visible =
          rect.width > 1 &&
          rect.height > 1 &&
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          element.getAttribute("aria-hidden") !== "true"
        const clipped =
          visible &&
          text.length > 0 &&
          (element.scrollWidth > element.clientWidth + 2 ||
            element.scrollHeight > element.clientHeight + 2)

        return clipped
          ? {
              client: `${element.clientWidth}x${element.clientHeight}`,
              label: text.slice(0, 90),
              scroll: `${element.scrollWidth}x${element.scrollHeight}`,
              tag: element.tagName.toLowerCase(),
            }
          : null
      })
      .filter(Boolean)
    const panelRadii = [
      ...document.querySelectorAll(".vpw-card, .vpw-panel, [data-slot='card']"),
    ]
      .map((element) => {
        const rect = element.getBoundingClientRect()
        if (rect.width < 10 || rect.height < 10) return null
        return Number.parseFloat(getComputedStyle(element).borderTopLeftRadius)
      })
      .filter((radius): radius is number => radius !== null)
    const main = document.querySelector("main")
    const mainRect = main?.getBoundingClientRect()

    return {
      bodyScrollWidth: document.body.scrollWidth,
      clippedControls,
      documentScrollWidth: documentElement.scrollWidth,
      mainHeight: mainRect?.height ?? 0,
      maxPanelRadius: Math.max(0, ...panelRadii),
      panelRadiusOver8Count: panelRadii.filter((radius) => radius > 8.1).length,
      viewportWidth: documentElement.clientWidth,
    }
  })
  const context = `${route.id} ${theme} ${viewport.label}`

  expect(
    metrics.documentScrollWidth,
    `${context} document width`,
  ).toBeLessThanOrEqual(metrics.viewportWidth + 1)
  expect(metrics.bodyScrollWidth, `${context} body width`).toBeLessThanOrEqual(
    metrics.viewportWidth + 1,
  )
  expect(metrics.clippedControls, `${context} clipped controls`).toEqual([])
  expect(metrics.panelRadiusOver8Count, `${context} panel radii`).toBe(0)
  expect(
    metrics.maxPanelRadius,
    `${context} max panel radius`,
  ).toBeLessThanOrEqual(8.1)
  expect(metrics.mainHeight, `${context} main content height`).toBeGreaterThan(
    120,
  )
}

async function captureRouteScreenshot({
  page,
  route,
  theme,
  viewport,
}: {
  page: Page
  route: EvidenceRoute
  theme: Theme
  viewport: EvidenceViewport
}) {
  await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" })
  await page.setViewportSize({
    height: viewport.height,
    width: viewport.width,
  })
  await page.goto(route.path)
  await route.assertReady(page)
  await page.evaluate(() => document.fonts.ready.then(() => undefined))
  await assertEvidenceLayout({ page, route, theme, viewport })

  const appShell = page.locator(".vpw-app-shell").first()
  const screenshot =
    (await appShell.count()) > 0
      ? await appShell.screenshot()
      : await page.screenshot({ fullPage: false })
  const fileNames = [
    explicitScreenshotName(route.id, theme, viewport.label),
    ...(legacyScreenshotAliases.get(
      aliasKey(route.id, theme, viewport.label),
    ) ?? []),
  ]

  for (const fileName of fileNames) {
    writeFileSync(
      evidenceScreenshotPath("ui-productization", "screenshots", fileName),
      screenshot,
    )
  }
}

async function routeEntryScreenshotApi(page: Page) {
  await routeWorkbenchShell(page, {
    findings: [mockFinding],
    projects: [mockProject],
  })
}

async function routeEvidenceScreenshotApi(page: Page) {
  await page.addInitScript((projectId) => {
    window.localStorage.setItem("vpw.selectedProjectId", projectId)
  }, mockProject.id)
  await routeWorkbenchShell(page, {
    findings: evidenceFindings,
    projects: [mockProject],
  })

  await page.route("**/api/v1/providers/status", (route) =>
    fulfillJson(route, evidenceProviderStatus),
  )
  await page.route(`**/api/v1/projects/${mockProject.id}/summary`, (route) =>
    fulfillJson(route, evidenceProjectSummary),
  )
  await page.route(`**/api/v1/projects/${mockProject.id}/dashboard`, (route) =>
    fulfillJson(route, {
      findings: {
        remediation_queue: {
          count: evidenceFindings.length,
          data: evidenceFindings,
        },
        signal_counts: {
          epss_buckets: { critical: 2, high: 0, low: 0, medium: 1 },
          high_epss: 2,
          internet_facing_criticals: 1,
        },
      },
      generated_at: timestamp,
      governance: evidenceGovernance,
      project_id: mockProject.id,
      runs: { count: 1, data: [evidenceRun] },
      summary: evidenceProjectSummary,
    }),
  )
  await page.route(`**/api/v1/projects/${mockProject.id}/runs/`, (route) =>
    fulfillJson(route, { count: 1, data: [evidenceRun] }),
  )
  await page.route(`**/api/v1/projects/${mockProject.id}/runs/?*`, (route) =>
    fulfillJson(route, { count: 1, data: [evidenceRun] }),
  )
  await page.route(`**/api/v1/runs/${runId}`, (route) =>
    fulfillJson(route, evidenceRun),
  )
  await page.route(`**/api/v1/runs/${runId}/summary`, (route) =>
    fulfillJson(route, evidenceRunSummary),
  )
  await page.route(`**/api/v1/runs/${runId}/reports`, (route) =>
    fulfillJson(route, { count: 1, data: [evidenceReport] }),
  )
  await page.route(`**/api/v1/projects/${mockProject.id}/assets/`, (route) =>
    fulfillJson(route, { count: evidenceAssets.length, data: evidenceAssets }),
  )
  await page.route(`**/api/v1/projects/${mockProject.id}/assets/?*`, (route) =>
    fulfillJson(route, { count: evidenceAssets.length, data: evidenceAssets }),
  )
  await page.route(`**/api/v1/projects/${mockProject.id}/waivers/`, (route) =>
    fulfillJson(route, {
      count: evidenceWaivers.length,
      data: evidenceWaivers,
    }),
  )
  await page.route(`**/api/v1/projects/${mockProject.id}/waivers/?*`, (route) =>
    fulfillJson(route, {
      count: evidenceWaivers.length,
      data: evidenceWaivers,
    }),
  )
  await page.route(
    `**/api/v1/projects/${mockProject.id}/governance/rollups/`,
    (route) => fulfillJson(route, evidenceGovernance),
  )
  await page.route(
    `**/api/v1/projects/${mockProject.id}/governance/rollups/?*`,
    (route) => fulfillJson(route, evidenceGovernance),
  )
}

test("evidence: Workbench entry light and dark screenshots", async ({ page }) => {
  test.setTimeout(60_000)
  await routeEntryScreenshotApi(page)

  for (const theme of themes) {
    for (const viewport of evidenceViewports) {
      await captureRouteScreenshot({ page, route: entryRoute, theme, viewport })
    }
  }
})

for (const theme of themes) {
  test(`evidence: ${theme} productive scoped route screenshots`, async ({
    page,
  }) => {
    test.setTimeout(180_000)
    await routeEvidenceScreenshotApi(page)

    for (const route of workbenchRoutes) {
      for (const viewport of evidenceViewports) {
        await captureRouteScreenshot({ page, route, theme, viewport })
      }
    }
  })
}
