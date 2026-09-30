import type { WorkbenchPath } from "./workbench-navigation"

/** Paths from before the pages took their menu names; they redirect. */
export const legacyWorkbenchPaths: Readonly<Record<string, WorkbenchPath>> = {
  "/findings": "/triage",
  "/providers": "/data-sources",
  "/reports": "/evidence",
  "/waivers": "/risk-acceptance",
}

type RouteDetail = {
  description: string
  eyebrow: string
  title: string
  panelTitle: string
  panelDetail: string
}

export const routeDetails: Record<WorkbenchPath, RouteDetail> = {
  "/": {
    description:
      "Current risk posture, data trust, and next remediation priorities.",
    eyebrow: "Operate",
    title: "Overview",
    panelTitle: "Overview",
    panelDetail: "Current risk posture and next remediation priorities.",
  },
  "/projects": {
    description: "Create, select, and maintain local Workbench project scopes.",
    eyebrow: "Prepare",
    title: "Projects",
    panelTitle: "Projects",
    panelDetail: "Project scopes, imports, and evidence context.",
  },
  "/imports": {
    description:
      "Import supplied vulnerability evidence and review parser/provider results.",
    eyebrow: "Prepare",
    title: "Imports",
    panelTitle: "Imports",
    panelDetail: "Bring supplied evidence into the Workbench.",
  },
  "/triage": {
    description:
      "Prioritize known CVEs using risk signals, asset context, VEX, and accepted-risk state.",
    eyebrow: "Operate",
    title: "Triage",
    panelTitle: "Triage",
    panelDetail: "Decide what to remediate or accept next.",
  },
  "/risk-acceptance": {
    description:
      "Track accepted risk, review deadlines, expiry, and matched findings.",
    eyebrow: "Govern",
    title: "Risk Acceptance",
    panelTitle: "Risk Acceptance",
    panelDetail: "Track accepted risk, reviews, and expiry.",
  },
  "/assets": {
    description:
      "Maintain ownership, service, exposure, and criticality context for findings.",
    eyebrow: "Prepare",
    title: "Assets",
    panelTitle: "Assets",
    panelDetail: "Maintain asset context and ownership.",
  },
  "/data-sources": {
    description:
      "Check provider freshness, local snapshots, warnings, and evidence readiness.",
    eyebrow: "System",
    title: "Data Sources",
    panelTitle: "Data Sources",
    panelDetail: "Check provider freshness, snapshots, and evidence readiness.",
  },
  "/evidence": {
    description:
      "Generate, verify, and download audit-ready evidence for an import run.",
    eyebrow: "Report",
    title: "Evidence Center",
    panelTitle: "Evidence Center",
    panelDetail: "Generate, verify, and download evidence.",
  },
  "/policy": {
    description:
      "Set the EPSS and CVSS thresholds that decide each finding's priority, and the SLA each priority gets.",
    eyebrow: "Govern",
    title: "Priority Policy",
    panelTitle: "Priority Policy",
    panelDetail: "Priority thresholds and SLA targets per project.",
  },
  "/settings": {
    description:
      "Inspect local Workbench runtime, provider, and diagnostic state.",
    eyebrow: "System",
    title: "Workspace Settings",
    panelTitle: "Workspace Settings",
    panelDetail: "Local runtime and diagnostics.",
  },
}

export const unknownRouteDetail: RouteDetail = {
  description: "Current workspace route.",
  eyebrow: "Workbench",
  title: "Workspace",
  panelTitle: "Workbench",
  panelDetail: "Current workspace route",
}

export const findingDetailRouteDetail: RouteDetail = {
  description: "Explain evidence, risk, and decision rationale.",
  eyebrow: "Operate",
  title: "Finding detail",
  panelTitle: "Finding detail",
  panelDetail: "Explain evidence, risk, and decision rationale.",
}

const importsNewRouteDetail: RouteDetail = {
  description: "Upload supplied evidence and create findings for triage.",
  eyebrow: "Prepare",
  title: "New import",
  panelTitle: "New import",
  panelDetail: "Upload supplied evidence and create findings.",
}

const importsFormatsRouteDetail: RouteDetail = {
  description: "File formats and structure expectations for imports.",
  eyebrow: "Prepare",
  title: "Supported formats",
  panelTitle: "Supported formats",
  panelDetail: "Review supported import formats.",
}

function importsRunRouteDetail(pathname: string): RouteDetail {
  const [, rawRunId = ""] = pathname.match(/^\/imports\/runs\/([^/]+)/) ?? []
  const runId = decodeRouteSegment(rawRunId)
  const shortRunId = runId ? runId.slice(0, 8) : "selected"
  return {
    description: "Review parser results, source evidence, diagnostics, and triage actions.",
    eyebrow: "Prepare",
    title: `Import run ${shortRunId}`,
    panelTitle: "Import run",
    panelDetail: "Review import run details.",
  }
}

const routePathOrder: readonly WorkbenchPath[] = [
  "/projects",
  "/imports",
  "/triage",
  "/risk-acceptance",
  "/policy",
  "/assets",
  "/data-sources",
  "/evidence",
  "/settings",
  "/",
]

export function workbenchPathFromPathname(
  pathname: string,
): WorkbenchPath | null {
  if (pathname === "/" || pathname === "") return "/"
  // A finding's detail page belongs to Triage.
  if (pathname.startsWith("/findings/")) return "/triage"
  const legacy = legacyWorkbenchPaths[pathname.replace(/\/+$/, "")]
  if (legacy) return legacy
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
  pathname: string,
  routePath: WorkbenchPath | null,
): RouteDetail {
  if (routePath === "/triage" && /^\/findings\/[^/]+/.test(pathname)) {
    return findingDetailRouteDetail
  }
  if (routePath === "/imports") {
    if (pathname === "/imports/new") return importsNewRouteDetail
    if (pathname === "/imports/formats") return importsFormatsRouteDetail
    if (/^\/imports\/runs\/[^/]+/.test(pathname)) {
      return importsRunRouteDetail(pathname)
    }
  }
  if (routePath) return routeDetails[routePath]
  return unknownRouteDetail
}

function decodeRouteSegment(value: string) {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}
