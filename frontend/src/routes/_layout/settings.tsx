import { createFileRoute } from "@tanstack/react-router"

import { SettingsRoute } from "../../workbench/routes/SettingsRoute"

export const Route = createFileRoute("/_layout/settings")({
  component: SettingsRoute,
})
