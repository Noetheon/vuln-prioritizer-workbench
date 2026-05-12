import { createFileRoute } from "@/lib/router"

import { WaiversRoute } from "../../workbench/routes/WaiversRoute"

export const Route = createFileRoute("/_layout/waivers")({
  component: WaiversRoute,
})
