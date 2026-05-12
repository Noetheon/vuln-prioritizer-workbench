import { createFileRoute } from "@/lib/router"

import { ImportsRoute } from "../../workbench/routes/ImportsRoute"

export const Route = createFileRoute("/_layout/imports")({
  component: ImportsRoute,
})
