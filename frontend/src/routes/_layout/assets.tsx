import { createFileRoute } from "@tanstack/react-router"

import { AssetsRoute } from "../../workbench/routes/AssetsRoute"

export const Route = createFileRoute("/_layout/assets")({
  component: AssetsRoute,
})
