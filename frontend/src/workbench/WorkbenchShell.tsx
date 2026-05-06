import { type ReactNode, Suspense } from "react"
import { useLocation } from "@tanstack/react-router"
import { ProductAppShell, type WorkbenchPath } from "../components/app/AppShell"
import { LoadingSkeleton } from "../components/states"
import { routeDetails } from "../lib/app-route-config"
import { useWorkbenchContext, WorkbenchProvider } from "./WorkbenchContext"

type WorkbenchShellProps = {
  children: ReactNode
  routePath?: WorkbenchPath
}

function workbenchPathFromPathname(pathname: string): WorkbenchPath {
  if (pathname === "/" || pathname === "") return "/"
  if (pathname.startsWith("/projects")) return "/projects"
  if (pathname.startsWith("/imports")) return "/imports"
  if (pathname.startsWith("/findings")) return "/findings"
  if (pathname.startsWith("/waivers")) return "/waivers"
  if (pathname.startsWith("/assets")) return "/assets"
  if (pathname.startsWith("/providers")) return "/providers"
  if (pathname.startsWith("/reports")) return "/reports"
  if (pathname.startsWith("/settings")) return "/settings"
  return "/"
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
  const routeDetail = routeDetails[activeRoutePath]
  const isFindingDetail =
    activeRoutePath === "/findings" && /^\/findings\/[^/]+$/.test(location.pathname)
  const hideStatusStrip = activeRoutePath === "/" || activeRoutePath === "/findings"

  return (
    <ProductAppShell
      activePath={activeRoutePath}
      currentUser={currentUser}
      eyebrow={routeDetail.eyebrow}
      hideStatusStrip={hideStatusStrip || Boolean(isFindingDetail)}
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
