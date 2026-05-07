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
  exposure: "internet_facing",
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
    await page.route(`**/api/v1/projects/${project.id}/summary`, (route) =>
      route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
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
        }),
      }),
    )
    await page.route(`**/api/v1/projects/${project.id}/findings/?*`, (route) =>
      route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ data: findings, count: findings.length }),
      }),
    )
  }
}
