import { createFileRoute } from "@/lib/router"

import { ProvidersRoute } from "../../workbench/routes/ProvidersRoute"

export const Route = createFileRoute("/_layout/providers")({
  component: ProvidersRoute,
})
