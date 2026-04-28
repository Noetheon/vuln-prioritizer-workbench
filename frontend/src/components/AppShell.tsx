import {
  ChevronDown,
  ClipboardList,
  Database,
  FileArchive,
  FolderPlus,
  Folders,
  Gavel,
  KeyRound,
  LayoutDashboard,
  LineChart,
  ListFilter,
  Search,
  Settings,
  ShieldCheck,
  ShieldQuestion,
  X
} from "lucide-react";
import { NavLink, Outlet, useLocation, useNavigate, useParams } from "react-router-dom";

import ProviderChips from "./ProviderChips";
import { ErrorPanel, LoadingPanel } from "./QueryState";
import { useSessionToken } from "../hooks/useSessionToken";
import { useProject, useProjects, useProviderStatus } from "../hooks/useWorkbenchQueries";

const navItems = [
  { to: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "imports/new", label: "Import", icon: ClipboardList },
  { to: "artifacts", label: "Artifacts", icon: FileArchive },
  { to: "findings", label: "Findings", icon: ListFilter },
  { to: "governance", label: "Governance", icon: Gavel },
  { to: "assets", label: "Assets", icon: Database },
  { to: "waivers", label: "Waivers", icon: ShieldQuestion },
  { to: "coverage", label: "Coverage", icon: LineChart },
  { to: "vulnerabilities", label: "Intelligence", icon: Search },
  { to: "settings", label: "Settings", icon: Settings }
];

export default function AppShell() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { token, hasToken, promptForToken, clearToken } = useSessionToken();
  const projectQuery = useProject(projectId);
  const projectsQuery = useProjects();
  const providerQuery = useProviderStatus();

  if (projectQuery.isLoading) {
    return <LoadingPanel as="main" label="Loading project" />;
  }

  if (projectQuery.error) {
    return <ErrorPanel as="main" error={projectQuery.error} />;
  }

  const project = projectQuery.data;
  const projects = projectsQuery.data?.items ?? [];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">
            <ShieldCheck aria-hidden="true" size={22} />
          </div>
          <div>
            <span>Workbench</span>
            <strong>Vuln Prioritizer</strong>
          </div>
        </div>

        <label className="project-switcher">
          Project
          <span>
            <select
              value={project?.id ?? ""}
              onChange={(event) => navigate(`/projects/${event.target.value}/dashboard`)}
              disabled={projects.length <= 1}
            >
              {project ? (
                <option value={project.id}>{project.name}</option>
              ) : null}
              {projects
                .filter((item) => item.id !== project?.id)
                .map((item) => (
                  <option value={item.id} key={item.id}>
                    {item.name}
                  </option>
                ))}
            </select>
            <ChevronDown aria-hidden="true" size={16} />
          </span>
        </label>

        <nav className="sidebar-nav" aria-label="Core triage">
          <NavLink to="/projects">
            <Folders aria-hidden="true" size={17} />
            Projects
          </NavLink>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink to={item.to} key={item.to}>
                <Icon aria-hidden="true" size={17} />
                {item.label}
              </NavLink>
            );
          })}
          <NavLink to="/new">
            <FolderPlus aria-hidden="true" size={17} />
            New project
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <span>API-backed workbench</span>
          <strong>{project?.name ?? "No project"}</strong>
        </div>
      </aside>

      <div className="workbench">
        <header className="topbar">
          <div>
            <span className="route-label">{routeLabel(location.pathname)}</span>
            <h1>{project?.name ?? "Workbench"}</h1>
          </div>
          <div className="topbar-actions">
            <ProviderChips status={providerQuery.data} compact />
            <button className="icon-text-button" type="button" onClick={promptForToken}>
              <KeyRound aria-hidden="true" size={16} />
              {hasToken ? "Token set" : "API token"}
            </button>
            {token ? (
              <button className="icon-button" type="button" onClick={clearToken} aria-label="Clear API token">
                <X aria-hidden="true" size={16} />
              </button>
            ) : null}
          </div>
        </header>
        <Outlet />
      </div>
    </div>
  );
}

function routeLabel(pathname: string): string {
  if (pathname.includes("/imports")) {
    return "Import";
  }
  if (pathname.includes("/artifacts") || pathname.includes("/runs/")) {
    return "Artifacts";
  }
  if (pathname.includes("/governance")) {
    return "Governance";
  }
  if (pathname.includes("/assets")) {
    return "Assets";
  }
  if (pathname.includes("/waivers")) {
    return "Waivers";
  }
  if (pathname.includes("/coverage")) {
    return "Coverage";
  }
  if (pathname.includes("/attack/techniques/")) {
    return "Technique detail";
  }
  if (pathname.includes("/vulnerabilities")) {
    return "Intelligence";
  }
  if (pathname.includes("/settings")) {
    return "Settings";
  }
  if (pathname.includes("/findings/")) {
    return "Finding detail";
  }
  if (pathname.includes("/findings")) {
    return "Findings";
  }
  return "Dashboard";
}
