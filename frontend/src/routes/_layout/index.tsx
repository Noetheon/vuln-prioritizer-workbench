import { createFileRoute } from "@tanstack/react-router"

import { App } from "../../App"

export const Route = createFileRoute("/_layout/")({
  component: App,
})
