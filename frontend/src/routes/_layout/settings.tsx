import { createFileRoute } from "@/lib/router"

import { SettingsRoute } from "../../workbench/routes/SettingsRoute"

export const Route = createFileRoute("/_layout/settings")({
  component: SettingsRoute,
})
