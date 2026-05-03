import { createFileRoute } from "@tanstack/react-router"

import { FindingDetailRoute } from "../../workbench/routes/FindingDetailRoute"

export const Route = createFileRoute("/_layout/findings/$findingId")({
  component: FindingDetailRoute,
})
