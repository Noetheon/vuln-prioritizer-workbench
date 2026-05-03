import { createFileRoute } from "@tanstack/react-router"

import { DashboardRoute } from "../../workbench/routes/DashboardRoute"

export const Route = createFileRoute("/_layout/")({
  component: DashboardRoute,
})
