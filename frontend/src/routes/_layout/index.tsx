import { createFileRoute } from "@/lib/router"

import { DashboardRoute } from "../../workbench/routes/DashboardRoute"

export const Route = createFileRoute("/_layout/")({
  component: DashboardRoute,
})
