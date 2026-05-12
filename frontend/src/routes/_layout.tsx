import { createFileRoute, Outlet } from "@/lib/router"

import { WorkbenchShell } from "../workbench/WorkbenchShell"

export const Route = createFileRoute("/_layout")({
  component: () => (
    <WorkbenchShell>
      <Outlet />
    </WorkbenchShell>
  ),
})
