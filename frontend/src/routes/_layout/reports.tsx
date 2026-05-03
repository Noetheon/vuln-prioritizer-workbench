import { createFileRoute } from "@tanstack/react-router"

import { ReportsRoute } from "../../workbench/routes/ReportsRoute"

export const Route = createFileRoute("/_layout/reports")({
  component: ReportsRoute,
})
