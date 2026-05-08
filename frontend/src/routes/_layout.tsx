import { createFileRoute, Outlet, redirect } from "@tanstack/react-router"

import { hasAuthenticatedSession } from "../lib/session-auth"
import { WorkbenchShell } from "../workbench/WorkbenchShell"

export const Route = createFileRoute("/_layout")({
  beforeLoad: async () => {
    if (!(await hasAuthenticatedSession())) {
      throw redirect({ search: {} as never, to: "/login" })
    }
  },
  component: () => (
    <WorkbenchShell>
      <Outlet />
    </WorkbenchShell>
  ),
})
