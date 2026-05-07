import type { Page } from "@playwright/test"

type MockProject = {
  created_at: string
  description: string
  id: string
  name: string
  owner_id: string
  updated_at: string
}

type MockFinding = {
  asset_id: string
  asset_key: string
  asset_name: string
  business_service: string
  component_id: string | null
  component_name: string
  component_purl: string
  component_version: string
  created_at: string
  cve_id: string
  cvss_base_score: number
  epss: number
  exposure: string
  first_seen_at: string
  id: string
  in_kev: boolean
  last_seen_at: string
  owner: string
  priority: string
  project_id: string
  rationale: string
  recommended_action: string
  risk_score: number
  status: string
  updated_at: string
  vulnerability_id: string
}

type RouteWorkbenchShellOptions = {
  findings?: MockFinding[]
  onFindingsRequest?: (url: URL) => void
  projects?: MockProject[]
}

export const mockProject: MockProject = {
  created_at: "2025-01-01T00:00:00Z",
  description: "Critical payment processing workloads.",
  id: "project-1",
  name: "Payments Platform",
  owner_id: "demo-user",
  updated_at: "2025-01-02T00:00:00Z",
}

export const mockFinding: MockFinding = {
  asset_id: "asset-1",
  asset_key: "build-host-1",
  asset_name: "build-host-1",
  business_service: "payments",
  component_id: null,
  component_name: "xz",
  component_purl: "pkg:apk/alpine/xz@5.6.0-r0",
  component_version: "5.6.0",
  created_at: "2025-01-01T00:00:00Z",
  cve_id: "CVE-2024-3094",
  cvss_base_score: 10,
  epss: 0.92,
  exposure: "internet-facing",
  first_seen_at: "2025-01-01T00:00:00Z",
  id: "finding-1",
  in_kev: true,
  last_seen_at: "2025-01-02T00:00:00Z",
  owner: "platform",
  priority: "critical",
  project_id: mockProject.id,
  rationale: "Known exploited dependency in a critical runtime.",
  recommended_action: "Patch xz.",
  risk_score: 9.8,
  status: "open",
  updated_at: "2025-01-02T00:00:00Z",
  vulnerability_id: "CVE-2024-3094",
}

export async function routeWorkbenchShell(
  page: Page,
  options: RouteWorkbenchShellOptions = {},
) {
  const projects = options.projects ?? []
  const findings = options.findings ?? []
  const onFindingsRequest = options.onFindingsRequest
  await page.addInitScript(() => {
    // biome-ignore lint/suspicious/noDocumentCookie: Playwright sets a mock readable CSRF cookie before app boot.
    document.cookie = "vpw_csrf_token=mock-csrf; Path=/; SameSite=Strict"
  })

  await page.route("**/api/v1/users/me", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        id: "demo-user",
        email: "admin@example.com",
        full_name: "Admin",
        is_active: true,
        is_superuser: true,
        created_at: "2025-01-01T00:00:00Z",
      }),
    }),
  )
  await page.route("**/api/v1/workbench/status", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        app: "Vuln Prioritizer Workbench",
        status: "ready",
        core_package: "vuln_prioritizer",
        core_version: "demo",
        database_status: "ready",
        schema_status: "ready",
      }),
    }),
  )
  await page.route("**/api/v1/providers/status", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        status: "ok",
        snapshot_mode: "demo",
        cache_age_seconds: 0,
        last_sync: "2025-04-30T10:00:00Z",
        warnings: [],
        snapshot: {
          id: "demo",
          mode: "demo",
          missing: false,
          selected_sources: ["epss", "kev"],
        },
        sources: [],
      }),
    }),
  )
  await page.route("**/api/v1/utils/health-check/", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ status: "ok" }),
    }),
  )
  await page.route("**/api/v1/findings/*/explain", (route) => {
    const findingId = route.request().url().split("/findings/")[1].split("/")[0]
    const finding = findings.find((item) => item.id === findingId)
    if (!finding) {
      return route.fulfill({
        contentType: "application/json",
        status: 404,
        body: JSON.stringify({ detail: "Finding not found" }),
      })
    }
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        cve_id: finding.cve_id,
        finding_id: finding.id,
        priority: finding.priority,
        priority_rank: 0,
        project_id: finding.project_id,
        rationale: finding.rationale,
        recommended_action: finding.recommended_action,
        risk_score: finding.risk_score,
      }),
    })
  })
  await page.route("**/api/v1/findings/*", (route) => {
    const findingId = route.request().url().split("/findings/")[1].split("?")[0]
    const finding = findings.find((item) => item.id === findingId)
    if (!finding) {
      return route.fulfill({
        contentType: "application/json",
        status: 404,
        body: JSON.stringify({ detail: "Finding not found" }),
      })
    }
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ...finding,
        attack_context: null,
        occurrences: [],
      }),
    })
  })
  await page.route("**/api/v1/projects/", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: projects, count: projects.length }),
    }),
  )
  await page.route("**/api/v1/projects/?*", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ data: projects, count: projects.length }),
    }),
  )
  for (const project of projects) {
    const projectSummary = {
      counts_by_priority: { critical: findings.length },
      counts_by_status: { open: findings.length },
      cvss_known_count: findings.length,
      epss_hits: findings.filter((finding) => finding.epss > 0).length,
      finding_count: findings.length,
      kev_hits: findings.filter((finding) => finding.in_kev).length,
      latest_run_id: null,
      latest_run_status: null,
      latest_run_summary: {},
      open_finding_count: findings.length,
      project_id: project.id,
      provider_degraded: false,
    }
    await page.route(`**/api/v1/projects/${project.id}/summary`, (route) =>
      route.fulfill({
        contentType: "application/json",
        body: JSON.stringify(projectSummary),
      }),
    )
    await page.route(`**/api/v1/projects/${project.id}/dashboard`, (route) =>
      route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          findings: {
            remediation_queue: { data: findings, count: findings.length },
            signal_counts: {
              high_epss: findings.filter((finding) => finding.epss >= 0.7).length,
              internet_facing_criticals: findings.filter(
                (finding) =>
                  finding.priority === "critical" &&
                  finding.exposure === "internet-facing",
              ).length,
              epss_buckets: {
                low: findings.filter(
                  (finding) => finding.epss >= 0 && finding.epss <= 0.25,
                ).length,
                medium: findings.filter(
                  (finding) => finding.epss >= 0.25 && finding.epss <= 0.5,
                ).length,
                high: findings.filter(
                  (finding) => finding.epss >= 0.5 && finding.epss <= 0.7,
                ).length,
                critical: findings.filter((finding) => finding.epss >= 0.7)
                  .length,
              },
            },
          },
          generated_at: "2025-01-02T00:00:00Z",
          governance: {
            assets: [],
            environments: [],
            generated_at: "2025-01-02T00:00:00Z",
            owners: [],
            project_id: project.id,
            services: [],
            top_assets_by_risk: [],
            top_services_by_risk: [],
          },
          project_id: project.id,
          runs: { data: [], count: 0 },
          summary: projectSummary,
        }),
      }),
    )
    await page.route(`**/api/v1/projects/${project.id}/findings/?*`, (route) =>
      {
        const url = new URL(route.request().url())
        onFindingsRequest?.(url)
        const { data, count } = mockFindingsPage(findings, url)
        return route.fulfill({
          contentType: "application/json",
          body: JSON.stringify({ data, count }),
        })
      },
    )
  }
}

function numericParam(url: URL, key: string) {
  const value = url.searchParams.get(key)
  if (!value) return null
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function boolParam(url: URL, key: string) {
  const value = url.searchParams.get(key)
  if (value === "true") return true
  if (value === "false") return false
  return null
}

function compareNumber(
  a: number | null | undefined,
  b: number | null | undefined,
  direction: string,
) {
  const aValue = a ?? Number.NEGATIVE_INFINITY
  const bValue = b ?? Number.NEGATIVE_INFINITY
  return direction === "asc" ? aValue - bValue : bValue - aValue
}

function compareText(
  a: string | null | undefined,
  b: string | null | undefined,
  direction: string,
) {
  const compared = String(a ?? "").localeCompare(String(b ?? ""), undefined, {
    numeric: true,
    sensitivity: "base",
  })
  return direction === "asc" ? compared : -compared
}

function mockFindingsPage(findings: MockFinding[], url: URL) {
  const priority = url.searchParams.get("priority")
  const status = url.searchParams.get("status")
  const exposure = url.searchParams.get("exposure")
  const ownerService = url.searchParams.get("owner_service")?.trim().toLowerCase()
  const kev = boolParam(url, "kev")
  const assetId = url.searchParams.get("asset_id")
  const epssMin = numericParam(url, "epss_min")
  const epssMax = numericParam(url, "epss_max")
  const cvssMin = numericParam(url, "cvss_min")
  const cvssMax = numericParam(url, "cvss_max")
  const sort = url.searchParams.get("sort") ?? "operational"
  const direction = url.searchParams.get("direction") ?? "asc"
  const offset = numericParam(url, "offset") ?? 0
  const limit = numericParam(url, "limit") ?? 100
  const filtered = findings.filter((finding) => {
    if (priority && finding.priority !== priority) return false
    if (status && finding.status !== status) return false
    if (exposure && finding.exposure !== exposure) return false
    if (kev !== null && finding.in_kev !== kev) return false
    if (assetId && finding.asset_id !== assetId) return false
    if (
      ownerService &&
      !`${finding.owner} ${finding.business_service}`
        .toLowerCase()
        .includes(ownerService)
    ) {
      return false
    }
    if (epssMin !== null && finding.epss < epssMin) return false
    if (epssMax !== null && finding.epss > epssMax) return false
    if (cvssMin !== null && finding.cvss_base_score < cvssMin) return false
    if (cvssMax !== null && finding.cvss_base_score > cvssMax) return false
    return true
  })
  const sorted = [...filtered].sort((a, b) => {
    switch (sort) {
      case "score":
        return compareNumber(a.risk_score, b.risk_score, direction)
      case "epss":
        return compareNumber(a.epss, b.epss, direction)
      case "cvss":
        return compareNumber(a.cvss_base_score, b.cvss_base_score, direction)
      case "priority":
        return compareText(a.priority, b.priority, direction)
      case "status":
        return compareText(a.status, b.status, direction)
      case "cve":
        return compareText(a.cve_id, b.cve_id, direction)
      case "component":
        return compareText(a.component_name, b.component_name, direction)
      case "owner":
        return compareText(a.owner, b.owner, direction)
      case "last_seen":
        return compareText(a.last_seen_at, b.last_seen_at, direction)
      default:
        return 0
    }
  })
  return {
    count: sorted.length,
    data: sorted.slice(offset, offset + limit),
  }
}
