import type { WorkbenchPath } from "../components/app/AppShell"

export const routeDetails: Record<
  WorkbenchPath,
  {
    eyebrow: string
    title: string
    panelTitle: string
    panelDetail: string
  }
> = {
  "/": {
    eyebrow: "Security Operations",
    title: "Risk Operations",
    panelTitle: "Priority Queue",
    panelDetail: "Current project signal review",
  },
  "/projects": {
    eyebrow: "Workbench Projects",
    title: "Projects",
    panelTitle: "Projects",
    panelDetail:
      "Manage workbench projects, imported findings, runs, and evidence readiness.",
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
    panelTitle: "Remediation Queue",
    panelDetail: "Prioritized remediation worklist",
  },
  "/waivers": {
    eyebrow: "Risk Acceptance",
    title: "Waivers",
    panelTitle: "Waiver Register",
    panelDetail: "Scoped accepted-risk decisions and lifecycle review",
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
    eyebrow: "Evidence Center",
    title: "Evidence Center",
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

export function normalizeWorkbenchPath(pathname: string): WorkbenchPath {
  const normalized =
    pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname
  if (normalized.startsWith("/findings/")) {
    return "/findings"
  }
  return normalized in routeDetails ? (normalized as WorkbenchPath) : "/"
}

export function findingIdFromPath(pathname: string) {
  const normalized =
    pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname
  const match = normalized.match(/^\/findings\/([^/]+)$/)
  return match ? decodeURIComponent(match[1]) : null
}
