import { createFileRoute, Outlet, redirect } from "@tanstack/react-router"

import { isLoggedIn } from "../auth"
import { WorkbenchShell } from "../workbench/WorkbenchShell"

export const Route = createFileRoute("/_layout")({
  beforeLoad: () => {
    if (!isLoggedIn()) {
      throw redirect({ to: "/login" })
    }
  },
  component: () => (
    <WorkbenchShell>
      <Outlet />
    </WorkbenchShell>
  ),
})
