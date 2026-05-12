import { createFileRoute } from "@/lib/router"

import { ReportsRoute } from "../../workbench/routes/ReportsRoute"

export const Route = createFileRoute("/_layout/reports")({
  component: ReportsRoute,
})
