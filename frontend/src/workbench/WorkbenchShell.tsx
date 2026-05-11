import { type ReactNode, Suspense } from "react"
import { useLocation } from "@tanstack/react-router"
import { LoadingSkeleton } from "../components/states"
import {
  routeDetailFromPathname,
  workbenchPathFromPathname,
} from "../lib/app-route-config"
import type { WorkbenchPath } from "../lib/workbench-navigation"
import { ProductAppShell } from "./ProductAppShell"
import { useWorkbenchContext, WorkbenchProvider } from "./WorkbenchContext"

type WorkbenchShellProps = {
  children: ReactNode
  routePath?: WorkbenchPath | null
}

function WorkbenchShellFrame({ children, routePath }: WorkbenchShellProps) {
  const location = useLocation()
  const {
    currentUser,
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
      currentUser={currentUser}
      eyebrow={routeDetail.eyebrow}
      hideStatusStrip
      providerStatus={providerStatus}
      status={status}
      statusError={statusError}
      title={routeDetail.title}
    >
      <Suspense fallback={<LoadingSkeleton label="Loading Workbench route" />}>
        {children}
      </Suspense>
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
