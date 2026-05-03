import { Outlet, useLocation } from "@tanstack/react-router"

import { WorkbenchShell } from "../WorkbenchShell"

export function FindingsRoute() {
  const location = useLocation()
  const detailMatch = location.pathname.match(/^\/findings\/([^/]+)$/)
  if (detailMatch) {
    return <Outlet />
  }

  return <WorkbenchShell routePath="/findings" />
}
