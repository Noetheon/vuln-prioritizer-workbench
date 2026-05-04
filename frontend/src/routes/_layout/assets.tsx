import { createFileRoute } from "@tanstack/react-router"

import { AssetsRoute } from "../../components/assets"

export const Route = createFileRoute("/_layout/assets")({
  component: AssetsRoute,
})
