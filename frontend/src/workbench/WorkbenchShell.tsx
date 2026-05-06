import { type ReactNode, Suspense } from "react"
import { ProductAppShell, type WorkbenchPath } from "../components/app/AppShell"
import { LoadingSkeleton } from "../components/states"
import { routeDetails } from "../lib/app-route-config"
import { useWorkbenchContext, WorkbenchProvider } from "./WorkbenchContext"

type WorkbenchShellProps = {
  children: ReactNode
  routePath: WorkbenchPath
}

function WorkbenchShellFrame({ children, routePath }: WorkbenchShellProps) {
  const {
    currentUser,
    providerStatus,
    status,
    statusError,
  } = useWorkbenchContext()
  const routeDetail = routeDetails[routePath]
  const isFindingDetail = routePath === "/findings" && routeDetail.panelTitle
  const hideStatusStrip = routePath === "/" || routePath === "/findings"

  return (
    <ProductAppShell
      activePath={routePath}
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
