import { createFileRoute } from "@tanstack/react-router"

import { FindingsRoute } from "../../workbench/routes/FindingsRoute"

export const Route = createFileRoute("/_layout/findings")({
  component: FindingsRoute,
})
