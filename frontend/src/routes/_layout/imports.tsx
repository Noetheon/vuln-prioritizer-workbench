import { createFileRoute } from "@tanstack/react-router"

import { ImportsRoute } from "../../workbench/routes/ImportsRoute"

export const Route = createFileRoute("/_layout/imports")({
  component: ImportsRoute,
})
