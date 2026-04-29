import { createFileRoute } from "@tanstack/react-router"

import { App } from "../../App"

export const Route = createFileRoute("/_layout/findings/$findingId")({
  component: App,
})
