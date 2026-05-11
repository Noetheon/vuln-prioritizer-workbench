import { createFileRoute } from "@tanstack/react-router"

import { DesignSystemRoute } from "../../../workbench/routes/DesignSystemRoute"

export const Route = createFileRoute("/_layout/dev/design-system")({
  component: DesignSystemRoute,
})
