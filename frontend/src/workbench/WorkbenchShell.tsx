import { type ReactNode, Suspense } from "react"
import { useLocation } from "@/lib/router"
import { LoadingSkeleton } from "../components/states"
import {
  routeDetailFromPathname,
  workbenchPathFromPathname,
} from "../lib/app-route-config"
import type { WorkbenchPath } from "../lib/workbench-navigation"
import { ProductAppShell } from "./ProductAppShell"
import { RouteErrorBoundary } from "./RouteErrorBoundary"
import { useWorkbenchContext, WorkbenchProvider } from "./WorkbenchContext"

type WorkbenchShellProps = {
  children: ReactNode
  routePath?: WorkbenchPath | null
}

function WorkbenchShellFrame({ children, routePath }: WorkbenchShellProps) {
  const location = useLocation()
  const {
    providerStatus,
    status,
    statusError,
  } = useWorkbenchContext()
  const activeRoutePath = routePath ?? workbenchPathFromPathname(location.pathname)
  const routeDetail = routeDetailFromPathname(
    location.pathname,
    activeRoutePath,
  )

  return (
    <ProductAppShell
      activePath={activeRoutePath}
      eyebrow={routeDetail.eyebrow}
      hideStatusStrip
      providerStatus={providerStatus}
      status={status}
      statusError={statusError}
      title={routeDetail.title}
      navigationKey={`${location.pathname}${location.searchStr}`}
    >
      <RouteErrorBoundary
        key={location.pathname}
        resetKey={`${location.pathname}${location.searchStr}`}
      >
        <Suspense fallback={<LoadingSkeleton label="Loading Workbench route" />}>
          {children}
        </Suspense>
      </RouteErrorBoundary>
    </ProductAppShell>
  )
}

export function WorkbenchShell({ children, routePath }: WorkbenchShellProps) {
  return (
    <WorkbenchProvider>
      <WorkbenchShellFrame routePath={routePath}>{children}</WorkbenchShellFrame>
    </WorkbenchProvider>
  )
}
