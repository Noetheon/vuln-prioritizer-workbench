import { Link, useLocation, useNavigate } from "@tanstack/react-router"
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Database,
  FileArchive,
  FileInput,
  FolderKanban,
  Gauge,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Settings,
  ShieldCheck,
} from "lucide-react"
import { useEffect, useState } from "react"
import { clearAccessToken } from "./auth"
import {
  ApiError,
  type ProjectDecisionSummaryPublic,
  type ProjectPublic,
  ProjectsService,
  type ProviderStatusPublic,
  ProvidersService,
  type UserPublic,
  UsersService,
  WorkbenchService,
  type WorkbenchStatus,
} from "./client"

const workbenchNavigation = [
  { label: "Dashboard", icon: LayoutDashboard, to: "/" },
  { label: "Projects", icon: FolderKanban, to: "/projects" },
  { label: "Imports", icon: FileInput, to: "/imports" },
  { label: "Findings", icon: ListChecks, to: "/findings" },
  { label: "Assets", icon: ShieldCheck, to: "/assets" },
  { label: "Providers", icon: Database, to: "/providers" },
  { label: "Reports", icon: FileArchive, to: "/reports" },
  { label: "Settings", icon: Settings, to: "/settings" },
] as const

const routeDetails: Record<
  (typeof workbenchNavigation)[number]["to"],
  {
    eyebrow: string
    title: string
    panelTitle: string
    panelDetail: string
  }
> = {
  "/": {
    eyebrow: "VPW Template Migration",
    title: "Risk Operations",
    panelTitle: "Priority Queue",
    panelDetail: "Current project signal review",
  },
  "/projects": {
    eyebrow: "Workbench Projects",
    title: "Projects",
    panelTitle: "Project Coverage",
    panelDetail: "Visible workspaces and decision backlog",
  },
  "/imports": {
    eyebrow: "Workbench Imports",
    title: "Imports",
    panelTitle: "Import Queue",
    panelDetail: "Normalized scanner, SBOM, and CVE-list inputs",
  },
  "/findings": {
    eyebrow: "Workbench Findings",
    title: "Findings",
    panelTitle: "Finding Decisions",
    panelDetail: "Prioritized CVEs awaiting review",
  },
  "/assets": {
    eyebrow: "Workbench Assets",
    title: "Assets",
    panelTitle: "Asset Context",
    panelDetail: "Business and exposure context for ranking",
  },
  "/providers": {
    eyebrow: "Workbench Providers",
    title: "Providers",
    panelTitle: "Provider Signals",
    panelDetail: "NVD, EPSS, KEV, and local snapshot status",
  },
  "/reports": {
    eyebrow: "Workbench Reports",
    title: "Reports",
    panelTitle: "Evidence Outputs",
    panelDetail: "Report and evidence bundle readiness",
  },
  "/settings": {
    eyebrow: "Workbench Settings",
    title: "Settings",
    panelTitle: "User Settings",
    panelDetail: "Current authenticated user and workspace session",
  },
}

type WorkbenchPath = keyof typeof routeDetails

function normalizeWorkbenchPath(pathname: string): WorkbenchPath {
  const normalized =
    pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname
  return normalized in routeDetails ? (normalized as WorkbenchPath) : "/"
}

function isActivePath(currentPath: WorkbenchPath, targetPath: WorkbenchPath) {
  return currentPath === targetPath
}

const currentUserLabel = (user: UserPublic | null) =>
  user?.email ?? "Local workspace"

const settingsSummary = (user: UserPublic | null) => [
  {
    label: "Signed-in user",
    value: currentUserLabel(user),
  },
  {
    label: "Session",
    value: user ? "Authenticated" : "Loading",
  },
]

const timeline = [
  "Provider snapshot locked",
  "Trivy import normalized",
  "Evidence bundle verified",
]

function priorityCount(
  summary: ProjectDecisionSummaryPublic | null,
  priority: "Critical" | "High" | "Medium" | "Low",
) {
  return summary?.counts_by_priority?.[priority] ?? 0
}

function buildDashboardCards(
  summary: ProjectDecisionSummaryPublic | null,
  providerStatus: ProviderStatusPublic | null,
  loading: boolean,
) {
  const providerFreshness = formatProviderFreshness(providerStatus)
  return [
    {
      label: "Critical",
      value: loading ? "Loading" : String(priorityCount(summary, "Critical")),
      detail: "critical prioritized findings",
      icon: AlertTriangle,
      tone: "critical",
    },
    {
      label: "High",
      value: loading ? "Loading" : String(priorityCount(summary, "High")),
      detail: "high priority findings",
      icon: Gauge,
      tone: "high",
    },
    {
      label: "KEV",
      value: loading ? "Loading" : String(summary?.kev_hits ?? 0),
      detail: "CISA catalog matches",
      icon: ShieldCheck,
      tone: "kev",
    },
    {
      label: "Provider Freshness",
      value: providerFreshness.value,
      detail: providerFreshness.detail,
      icon: Database,
      tone: providerFreshness.tone,
    },
    {
      label: "Latest Runs",
      value: loading ? "Loading" : formatRunStatus(summary?.latest_run_status),
      detail: latestRunDetail(summary),
      icon: Activity,
      tone: "run",
    },
  ]
}

function buildSummaryRows(summary: ProjectDecisionSummaryPublic | null) {
  return [
    {
      label: "Open findings",
      value: String(summary?.open_finding_count ?? 0),
      detail: "open, in review, or remediating",
    },
    {
      label: "Total findings",
      value: String(summary?.finding_count ?? 0),
      detail: "persisted findings in project",
    },
    {
      label: "EPSS hits",
      value: String(summary?.epss_hits ?? 0),
      detail: "findings with EPSS context",
    },
    {
      label: "Known CVSS",
      value: String(summary?.cvss_known_count ?? 0),
      detail: "findings with CVSS base score",
    },
  ]
}

function formatProviderFreshness(providerStatus: ProviderStatusPublic | null) {
  if (providerStatus === null) {
    return {
      value: "Loading",
      detail: "provider status loading",
      tone: "run",
    }
  }
  if (providerStatus.status === "ok") {
    return {
      value: "Fresh",
      detail:
        providerStatus.cache_age_seconds !== null &&
        providerStatus.cache_age_seconds !== undefined
          ? `${formatCacheAge(providerStatus.cache_age_seconds)} old`
          : providerStatus.snapshot_mode,
      tone: "kev",
    }
  }
  return {
    value: "Needs sync",
    detail:
      providerStatus.last_error ??
      providerStatus.warnings?.[0] ??
      "No snapshot recorded",
    tone: "high",
  }
}

function formatRunStatus(
  status: ProjectDecisionSummaryPublic["latest_run_status"],
) {
  return status ? status.replaceAll("_", " ") : "No runs"
}

function latestRunDetail(summary: ProjectDecisionSummaryPublic | null) {
  if (!summary?.latest_run_id) {
    return "import required"
  }
  return `run ${summary.latest_run_id.slice(0, 8)}`
}

function apiErrorMessage(prefix: string, caught: unknown) {
  if (caught instanceof ApiError) {
    const detail = apiErrorDetail(caught.body)
    return `${prefix}: ${detail ?? caught.message ?? `HTTP ${caught.status}`}`
  }
  return `${prefix}: unexpected client error`
}

function apiErrorDetail(body: unknown) {
  if (typeof body !== "object" || body === null || !("detail" in body)) {
    return null
  }
  const detail = (body as { detail?: unknown }).detail
  if (typeof detail === "string" && detail.trim()) {
    return detail
  }
  if (Array.isArray(detail)) {
    return "validation failed"
  }
  return null
}

export function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const currentPath = normalizeWorkbenchPath(location.pathname)
  const routeDetail = routeDetails[currentPath]
  const [status, setStatus] = useState<WorkbenchStatus | null>(null)
  const [providerStatus, setProviderStatus] =
    useState<ProviderStatusPublic | null>(null)
  const [currentUser, setCurrentUser] = useState<UserPublic | null>(null)
  const [statusError, setStatusError] = useState("")
  const [projects, setProjects] = useState<ProjectPublic[]>([])
  const [selectedProjectId, setSelectedProjectId] = useState("")
  const [projectSummary, setProjectSummary] =
    useState<ProjectDecisionSummaryPublic | null>(null)
  const [projectListLoading, setProjectListLoading] = useState(true)
  const [summaryLoading, setSummaryLoading] = useState(false)
  const [dashboardError, setDashboardError] = useState("")
  const selectedProject =
    projects.find((project) => project.id === selectedProjectId) ?? null
  const dashboardLoading = projectListLoading || summaryLoading
  const dashboardCards = buildDashboardCards(
    projectSummary,
    providerStatus,
    dashboardLoading,
  )
  const summaryRows = buildSummaryRows(projectSummary)

  useEffect(() => {
    let isMounted = true

    async function loadTemplateState() {
      try {
        const [workbenchStatus, providerStatusResponse, user] =
          await Promise.all([
            WorkbenchService.templateWorkbenchStatus(),
            ProvidersService.readProviderStatus(),
            UsersService.readUserMe(),
          ])
        if (isMounted) {
          setStatus(workbenchStatus)
          setProviderStatus(providerStatusResponse)
          setCurrentUser(user)
          setStatusError("")
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setStatusError("Backend adapter unavailable")
        }
      }
    }

    void loadTemplateState()
    return () => {
      isMounted = false
    }
  }, [navigate])

  useEffect(() => {
    let isMounted = true

    async function loadProjects() {
      setProjectListLoading(true)
      setDashboardError("")
      try {
        const projectPage = await ProjectsService.readProjects()
        if (isMounted) {
          setProjects(projectPage.data)
          setSelectedProjectId((previousProjectId) =>
            projectPage.data.some((project) => project.id === previousProjectId)
              ? previousProjectId
              : (projectPage.data[0]?.id ?? ""),
          )
          if (projectPage.data.length === 0) {
            setProjectSummary(null)
          }
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setProjects([])
          setSelectedProjectId("")
          setProjectSummary(null)
          setDashboardError(apiErrorMessage("Project list unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setProjectListLoading(false)
        }
      }
    }

    void loadProjects()
    return () => {
      isMounted = false
    }
  }, [navigate])

  useEffect(() => {
    let isMounted = true

    async function loadProjectSummary() {
      if (!selectedProjectId) {
        setProjectSummary(null)
        setSummaryLoading(false)
        return
      }

      setSummaryLoading(true)
      setDashboardError("")
      try {
        const summary = await ProjectsService.readProjectSummary({
          projectId: selectedProjectId,
        })
        if (isMounted) {
          setProjectSummary(summary)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setProjectSummary(null)
          setDashboardError(
            apiErrorMessage("Project summary unavailable", caught),
          )
        }
      } finally {
        if (isMounted) {
          setSummaryLoading(false)
        }
      }
    }

    void loadProjectSummary()
    return () => {
      isMounted = false
    }
  }, [navigate, selectedProjectId])

  async function signOut() {
    clearAccessToken()
    await navigate({ to: "/login" })
  }

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Workbench sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            VP
          </div>
          <div>
            <strong>Vuln Prioritizer</strong>
            <span>Workbench</span>
          </div>
        </div>
        <nav className="nav-list" aria-label="Workbench navigation">
          {workbenchNavigation.map((entry) => (
            <Link
              aria-current={
                isActivePath(currentPath, entry.to) ? "page" : undefined
              }
              className={
                isActivePath(currentPath, entry.to)
                  ? "nav-item active"
                  : "nav-item"
              }
              key={entry.label}
              to={entry.to}
            >
              <entry.icon aria-hidden="true" size={18} />
              <span>{entry.label}</span>
            </Link>
          ))}
        </nav>
        <div className="sidebar-footer">
          <KeyRound aria-hidden="true" size={18} />
          <span>{currentUserLabel(currentUser)}</span>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">{routeDetail.eyebrow}</span>
            <h1>{routeDetail.title}</h1>
          </div>
          <div
            className="status-strip"
            role="status"
            aria-label="Workspace health"
          >
            <span className="status-dot" aria-hidden="true" />
            <span>
              {status?.status === "ok" ? "Backend adapter online" : statusError}
            </span>
          </div>
          <button
            className="icon-button"
            type="button"
            aria-label="Sign out"
            onClick={signOut}
          >
            <LogOut aria-hidden="true" size={18} />
          </button>
        </header>

        <section
          className="template-status"
          aria-label="Template backend status"
        >
          <div>
            <span>Application</span>
            <strong>{status?.app ?? "Vuln Prioritizer Workbench"}</strong>
          </div>
          <div>
            <span>Core</span>
            <strong>
              {status?.core_package ?? "vuln_prioritizer"}{" "}
              {status?.core_version ?? ""}
            </strong>
          </div>
          <div>
            <span>Migration</span>
            <strong>{status?.migration.phase ?? "loading"}</strong>
          </div>
          <div>
            <span>Legacy mount</span>
            <strong>
              {status?.migration.legacy_workbench_mounted
                ? "enabled"
                : "disabled"}
            </strong>
          </div>
        </section>

        {currentPath === "/" ? (
          <>
            <section
              className="dashboard-toolbar"
              aria-label="Dashboard project context"
            >
              <label className="project-selector">
                <span>Current project</span>
                <select
                  aria-label="Current project"
                  disabled={dashboardLoading || projects.length === 0}
                  onChange={(event) => setSelectedProjectId(event.target.value)}
                  value={selectedProjectId}
                >
                  {projects.length === 0 ? (
                    <option value="">No projects</option>
                  ) : null}
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
              </label>
              <div className="project-context">
                <span>Summary source</span>
                <strong>
                  {selectedProject?.name ??
                    (projectListLoading ? "Loading" : "No project selected")}
                </strong>
              </div>
            </section>

            <section className="metric-grid" aria-label="Dashboard summary">
              {dashboardCards.map((card) => (
                <article
                  aria-label={`${card.label} summary card`}
                  className={`metric-card tone-${card.tone}`}
                  key={card.label}
                >
                  <card.icon aria-hidden="true" size={20} />
                  <div>
                    <span>{card.label}</span>
                    <strong>{card.value}</strong>
                    <small>{card.detail}</small>
                  </div>
                </article>
              ))}
            </section>
          </>
        ) : null}

        {currentPath === "/settings" ? (
          <section className="settings-summary" aria-label="User Settings">
            {settingsSummary(currentUser).map((entry) => (
              <div key={entry.label}>
                <span>{entry.label}</span>
                <strong>{entry.value}</strong>
              </div>
            ))}
          </section>
        ) : null}

        <section className="content-grid">
          <div className="work-panel">
            <div className="panel-header">
              <div>
                <h2>{routeDetail.panelTitle}</h2>
                <span>{routeDetail.panelDetail}</span>
              </div>
              <button
                className="icon-button"
                type="button"
                aria-label="Refresh queue"
              >
                <Activity aria-hidden="true" size={18} />
              </button>
            </div>

            <div className="dashboard-panel-body">
              {dashboardError ? (
                <p className="dashboard-alert" role="alert">
                  {dashboardError}
                </p>
              ) : null}

              {dashboardLoading ? (
                <p className="dashboard-state" role="status">
                  Loading dashboard summary
                </p>
              ) : null}

              {!dashboardLoading && !dashboardError && projects.length === 0 ? (
                <section
                  className="dashboard-empty"
                  aria-label="Dashboard empty state"
                >
                  <h3>No projects yet</h3>
                  <p>
                    Create a project or import a CVE list to populate the
                    dashboard.
                  </p>
                  <div className="empty-actions">
                    <Link className="primary-action" to="/projects">
                      Projects
                    </Link>
                    <Link className="secondary-action" to="/imports">
                      Imports
                    </Link>
                  </div>
                </section>
              ) : null}

              {!dashboardLoading &&
              !dashboardError &&
              selectedProject &&
              projectSummary !== null &&
              (projectSummary.finding_count ?? 0) === 0 ? (
                <section
                  className="dashboard-empty"
                  aria-label="No findings empty state"
                >
                  <h3>No findings in {selectedProject.name}</h3>
                  <p>
                    Import scanner, SBOM, or CVE-list data to create findings.
                  </p>
                  <div className="empty-actions">
                    <Link className="primary-action" to="/imports">
                      Imports
                    </Link>
                    <Link className="secondary-action" to="/projects">
                      Projects
                    </Link>
                  </div>
                </section>
              ) : null}

              {!dashboardLoading &&
              !dashboardError &&
              projectSummary !== null &&
              (projectSummary.finding_count ?? 0) > 0 ? (
                <dl
                  className="summary-list"
                  aria-label="Project decision summary"
                >
                  {summaryRows.map((row) => (
                    <div key={row.label}>
                      <dt>{row.label}</dt>
                      <dd>
                        <strong>{row.value}</strong>
                        <span>{row.detail}</span>
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : null}
            </div>
          </div>

          <div className="side-panel">
            <section
              className="provider-status-section"
              aria-label="Provider Status"
            >
              <div className="panel-header compact inline-header">
                <div>
                  <h2>Provider Status</h2>
                  <span>
                    {providerStatus?.snapshot.content_hash ??
                      "No snapshot recorded"}
                  </span>
                </div>
                <Database aria-hidden="true" size={18} />
              </div>

              <div
                className={`provider-state ${
                  providerStatus?.status === "ok" ? "ok" : "degraded"
                }`}
              >
                <span>{providerStatus?.status ?? "loading"}</span>
                <strong>{providerStatus?.snapshot_mode ?? "missing"}</strong>
              </div>

              <dl className="provider-facts">
                <div>
                  <dt>Snapshot mode</dt>
                  <dd>{providerStatus?.snapshot_mode ?? "missing"}</dd>
                </div>
                <div>
                  <dt>Last sync</dt>
                  <dd>{providerStatus?.last_sync ?? "N.A."}</dd>
                </div>
                <div>
                  <dt>Cache age</dt>
                  <dd>{formatCacheAge(providerStatus?.cache_age_seconds)}</dd>
                </div>
                <div>
                  <dt>Last error</dt>
                  <dd>
                    {providerStatus?.last_error ?? (statusError || "None")}
                  </dd>
                </div>
              </dl>

              <ul className="provider-sources" aria-label="Provider sources">
                {(providerStatus?.sources ?? fallbackProviderSources).map(
                  (source) => (
                    <li className="provider-source" key={source.name}>
                      <div>
                        <strong>{source.name.toUpperCase()}</strong>
                        <span>{source.value ?? "N.A."}</span>
                      </div>
                      <span
                        className={
                          source.available
                            ? "source-pill available"
                            : "source-pill"
                        }
                      >
                        {source.available ? "available" : "missing"}
                      </span>
                    </li>
                  ),
                )}
              </ul>

              {(providerStatus?.warnings ?? []).map((warning) => (
                <p className="provider-warning" key={warning}>
                  {warning}
                </p>
              ))}
            </section>

            <div className="panel-header compact">
              <div>
                <h2>Evidence Flow</h2>
                <span>Latest workspace events</span>
              </div>
              <GitBranch aria-hidden="true" size={18} />
            </div>
            <ol className="timeline">
              {timeline.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ol>
            <div className="coverage-block">
              <BarChart3 aria-hidden="true" size={20} />
              <div>
                <strong>ATT&CK coverage</strong>
                <span>
                  Top technique gaps remain visible for the next API slice.
                </span>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}

const fallbackProviderSources = [
  { name: "nvd", available: false, value: null },
  { name: "epss", available: false, value: null },
  { name: "kev", available: false, value: null },
]

function formatCacheAge(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) {
    return "N.A."
  }
  if (seconds < 60) {
    return `${seconds}s`
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m`
  }
  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)}h`
  }
  return `${Math.floor(seconds / 86400)}d`
}
