import { lazy, useEffect } from "react"
import { legacyWorkbenchPaths } from "./lib/app-route-config"
import { RouteParamsProvider, useLocation, useNavigate } from "./lib/router"
import type { WorkbenchPath } from "./lib/workbench-navigation"
import { WorkbenchShell } from "./workbench/WorkbenchShell"

type RouteMatch = {
  Component: React.ComponentType
  params: Record<string, string>
  // Set for a path from before the rename; the router replaces it.
  redirectTo?: WorkbenchPath
  routePath: WorkbenchPath | null
}

const AssetsRoute = lazy(() =>
  import("./workbench/routes/AssetsRoute").then((module) => ({
    default: module.AssetsRoute,
  })),
)
const DashboardRoute = lazy(() =>
  import("./workbench/routes/DashboardRoute").then((module) => ({
    default: module.DashboardRoute,
  })),
)
const FindingDetailRoute = lazy(() =>
  import("./workbench/routes/FindingDetailRoute").then((module) => ({
    default: module.FindingDetailRoute,
  })),
)
const FindingsRoute = lazy(() =>
  import("./workbench/routes/FindingsRoute").then((module) => ({
    default: module.FindingsRoute,
  })),
)
const ImportsRoute = lazy(() =>
  import("./workbench/routes/ImportsRoute").then((module) => ({
    default: module.ImportsRoute,
  })),
)
const ProjectsRoute = lazy(() =>
  import("./workbench/routes/ProjectsRoute").then((module) => ({
    default: module.ProjectsRoute,
  })),
)
const PolicyRoute = lazy(() =>
  import("./workbench/routes/PolicyRoute").then((module) => ({
    default: module.PolicyRoute,
  })),
)
const ProvidersRoute = lazy(() =>
  import("./workbench/routes/ProvidersRoute").then((module) => ({
    default: module.ProvidersRoute,
  })),
)
const ReportsRoute = lazy(() =>
  import("./workbench/routes/ReportsRoute").then((module) => ({
    default: module.ReportsRoute,
  })),
)
const SettingsRoute = lazy(() =>
  import("./workbench/routes/SettingsRoute").then((module) => ({
    default: module.SettingsRoute,
  })),
)
const WaiversRoute = lazy(() =>
  import("./workbench/routes/WaiversRoute").then((module) => ({
    default: module.WaiversRoute,
  })),
)

const staticRoutes: Record<string, Omit<RouteMatch, "params">> = {
  "/": { Component: DashboardRoute, routePath: "/" },
  "/assets": { Component: AssetsRoute, routePath: "/assets" },
  "/triage": { Component: FindingsRoute, routePath: "/triage" },
  "/imports": { Component: ImportsRoute, routePath: "/imports" },
  "/projects": { Component: ProjectsRoute, routePath: "/projects" },
  "/data-sources": { Component: ProvidersRoute, routePath: "/data-sources" },
  "/policy": { Component: PolicyRoute, routePath: "/policy" },
  "/evidence": { Component: ReportsRoute, routePath: "/evidence" },
  "/settings": { Component: SettingsRoute, routePath: "/settings" },
  "/risk-acceptance": { Component: WaiversRoute, routePath: "/risk-acceptance" },
}

function NotFoundRoute() {
  return (
    <section className="w-full px-1">
      <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] p-6">
        <p className="text-sm font-medium text-[var(--vpw-text-primary)]">
          Route not found
        </p>
      </div>
    </section>
  )
}

export function AppRouter() {
  const location = useLocation()
  const navigate = useNavigate()
  const match = routeMatch(location.pathname)
  const redirectTo = match.redirectTo

  useEffect(() => {
    if (redirectTo) {
      void navigate({ replace: true, search: location.searchStr, to: redirectTo })
    }
  }, [location.searchStr, navigate, redirectTo])

  return (
    <RouteParamsProvider params={match.params}>
      <WorkbenchShell routePath={match.routePath}>
        <match.Component />
      </WorkbenchShell>
    </RouteParamsProvider>
  )
}

export function routeMatch(pathname: string): RouteMatch {
  const normalizedPath = pathname.replace(/\/+$/, "") || "/"
  const importRunMatch = normalizedPath.match(/^\/imports\/runs\/([^/]+)$/)
  if (importRunMatch) {
    const runId = safeDecodeURIComponent(importRunMatch[1] ?? "")
    if (runId === null) {
      return { Component: NotFoundRoute, params: {}, routePath: null }
    }
    return {
      Component: ImportsRoute,
      params: { importsView: "run", runId },
      routePath: "/imports",
    }
  }
  if (normalizedPath === "/imports/new") {
    return {
      Component: ImportsRoute,
      params: { importsView: "new" },
      routePath: "/imports",
    }
  }
  if (normalizedPath === "/imports/formats") {
    return {
      Component: ImportsRoute,
      params: { importsView: "formats" },
      routePath: "/imports",
    }
  }
  const findingDetailMatch = normalizedPath.match(/^\/findings\/([^/]+)$/)
  if (findingDetailMatch) {
    const findingId = safeDecodeURIComponent(findingDetailMatch[1] ?? "")
    if (findingId === null) {
      return { Component: NotFoundRoute, params: {}, routePath: null }
    }
    return {
      Component: FindingDetailRoute,
      params: { findingId },
      routePath: "/triage",
    }
  }
  const staticMatch = staticRoutes[normalizedPath]
  if (staticMatch) {
    return { ...staticMatch, params: {} }
  }
  const legacyPath = legacyWorkbenchPaths[normalizedPath]
  const legacyMatch = legacyPath ? staticRoutes[legacyPath] : undefined
  if (legacyPath && legacyMatch) {
    return { ...legacyMatch, params: {}, redirectTo: legacyPath }
  }
  return { Component: NotFoundRoute, params: {}, routePath: null }
}

function safeDecodeURIComponent(value: string): string | null {
  try {
    return decodeURIComponent(value)
  } catch {
    return null
  }
}
