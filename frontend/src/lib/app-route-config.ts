import type { WorkbenchPath } from "./workbench-navigation"

type RouteDetail = {
  eyebrow: string
  title: string
  panelTitle: string
  panelDetail: string
}

export const routeDetails: Record<
  WorkbenchPath,
  RouteDetail
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
    panelTitle: "Workspace Settings",
    panelDetail: "Local workspace access, provider state, and diagnostics",
  },
}

export const unknownRouteDetail: RouteDetail = {
  eyebrow: "Workbench",
  title: "Workspace",
  panelTitle: "Workbench",
  panelDetail: "Current workspace route",
}

const routePathOrder: readonly WorkbenchPath[] = [
  "/projects",
  "/imports",
  "/findings",
  "/waivers",
  "/assets",
  "/providers",
  "/reports",
  "/settings",
  "/",
]

export function workbenchPathFromPathname(
  pathname: string,
): WorkbenchPath | null {
  if (pathname === "/" || pathname === "") return "/"
  for (const routePath of routePathOrder) {
    if (
      routePath !== "/" &&
      (pathname === routePath || pathname.startsWith(`${routePath}/`))
    ) {
      return routePath
    }
  }
  return null
}

export function routeDetailFromPathname(
  _pathname: string,
  routePath: WorkbenchPath | null,
): RouteDetail {
  if (routePath) return routeDetails[routePath]
  return unknownRouteDetail
}
