import { useNavigate } from "@tanstack/react-router"
import {
  Activity,
  AlertTriangle,
  BarChart3,
  FileArchive,
  FileInput,
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
  type UserPublic,
  UsersService,
  WorkbenchService,
  type WorkbenchStatus,
} from "./client"

const navItems = [
  { label: "Overview", icon: LayoutDashboard, active: true },
  { label: "Imports", icon: FileInput, active: false },
  { label: "Findings", icon: ListChecks, active: false },
  { label: "Reports", icon: FileArchive, active: false },
  { label: "Settings", icon: Settings, active: false },
]

const metrics = [
  {
    label: "Critical",
    value: "12",
    detail: "KEV or active risk",
    icon: AlertTriangle,
  },
  {
    label: "Prioritized",
    value: "148",
    detail: "ranked findings",
    icon: Gauge,
  },
  { label: "Evidence", value: "7", detail: "bundles ready", icon: FileArchive },
  {
    label: "Controls",
    value: "63%",
    detail: "coverage mapped",
    icon: ShieldCheck,
  },
]

const findings = [
  {
    cve: "CVE-2021-44228",
    asset: "commerce-api",
    priority: "Critical",
    signal: "KEV, EPSS 94%",
    state: "Needs Review",
  },
  {
    cve: "CVE-2023-34362",
    asset: "edge-transfer",
    priority: "High",
    signal: "ATT&CK mapped",
    state: "Ready",
  },
  {
    cve: "CVE-2024-3094",
    asset: "builder-image",
    priority: "High",
    signal: "supply-chain",
    state: "Blocked",
  },
]

const timeline = [
  "Provider snapshot locked",
  "Trivy import normalized",
  "Evidence bundle verified",
]

export function App() {
  const navigate = useNavigate()
  const [status, setStatus] = useState<WorkbenchStatus | null>(null)
  const [currentUser, setCurrentUser] = useState<UserPublic | null>(null)
  const [statusError, setStatusError] = useState("")

  useEffect(() => {
    let isMounted = true

    async function loadTemplateState() {
      try {
        const [workbenchStatus, user] = await Promise.all([
          WorkbenchService.templateWorkbenchStatus(),
          UsersService.readUserMe(),
        ])
        if (isMounted) {
          setStatus(workbenchStatus)
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

  async function signOut() {
    clearAccessToken()
    await navigate({ to: "/login" })
  }

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Workbench navigation">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            VP
          </div>
          <div>
            <strong>Vuln Prioritizer</strong>
            <span>Workbench</span>
          </div>
        </div>
        <nav className="nav-list">
          {navItems.map((item) => (
            <button
              className={item.active ? "nav-item active" : "nav-item"}
              key={item.label}
              type="button"
            >
              <item.icon aria-hidden="true" size={18} />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <KeyRound aria-hidden="true" size={18} />
          <span>{currentUser?.email ?? "Local workspace"}</span>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">VPW Template Migration</span>
            <h1>Risk Operations</h1>
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

        <section className="metric-grid" aria-label="Risk summary">
          {metrics.map((metric) => (
            <article className="metric-card" key={metric.label}>
              <metric.icon aria-hidden="true" size={20} />
              <div>
                <span>{metric.label}</span>
                <strong>{metric.value}</strong>
                <small>{metric.detail}</small>
              </div>
            </article>
          ))}
        </section>

        <section className="content-grid">
          <div className="work-panel">
            <div className="panel-header">
              <div>
                <h2>Priority Queue</h2>
                <span>Current project signal review</span>
              </div>
              <button
                className="icon-button"
                type="button"
                aria-label="Refresh queue"
              >
                <Activity aria-hidden="true" size={18} />
              </button>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>Asset</th>
                    <th>Priority</th>
                    <th>Signal</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.cve}>
                      <td>{finding.cve}</td>
                      <td>{finding.asset}</td>
                      <td>
                        <span
                          className={`severity ${finding.priority.toLowerCase()}`}
                        >
                          {finding.priority}
                        </span>
                      </td>
                      <td>{finding.signal}</td>
                      <td>{finding.state}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="side-panel">
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
