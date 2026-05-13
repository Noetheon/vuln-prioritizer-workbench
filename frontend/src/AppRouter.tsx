import { lazy } from "react"
import { RouteParamsProvider, useLocation } from "./lib/router"
import type { WorkbenchPath } from "./lib/workbench-navigation"
import { WorkbenchShell } from "./workbench/WorkbenchShell"

type RouteMatch = {
  Component: React.ComponentType
  params: Record<string, string>
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
  "/findings": { Component: FindingsRoute, routePath: "/findings" },
  "/imports": { Component: ImportsRoute, routePath: "/imports" },
  "/projects": { Component: ProjectsRoute, routePath: "/projects" },
  "/providers": { Component: ProvidersRoute, routePath: "/providers" },
  "/reports": { Component: ReportsRoute, routePath: "/reports" },
  "/settings": { Component: SettingsRoute, routePath: "/settings" },
  "/waivers": { Component: WaiversRoute, routePath: "/waivers" },
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
  const match = routeMatch(location.pathname)

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
  const findingDetailMatch = normalizedPath.match(/^\/findings\/([^/]+)$/)
  if (findingDetailMatch) {
    const findingId = safeDecodeURIComponent(findingDetailMatch[1] ?? "")
    if (findingId === null) {
      return { Component: NotFoundRoute, params: {}, routePath: null }
    }
    return {
      Component: FindingDetailRoute,
      params: { findingId },
      routePath: "/findings",
    }
  }
  const staticMatch = staticRoutes[normalizedPath]
  if (staticMatch) {
    return { ...staticMatch, params: {} }
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
