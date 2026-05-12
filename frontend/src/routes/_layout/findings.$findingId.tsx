import { createFileRoute } from "@/lib/router"

import { FindingDetailRoute } from "../../workbench/routes/FindingDetailRoute"

export const Route = createFileRoute("/_layout/findings/$findingId")({
  component: FindingDetailRoute,
})
