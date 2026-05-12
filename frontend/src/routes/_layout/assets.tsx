import { createFileRoute } from "@/lib/router"

import { AssetsRoute } from "../../workbench/routes/AssetsRoute"

export const Route = createFileRoute("/_layout/assets")({
  component: AssetsRoute,
})
