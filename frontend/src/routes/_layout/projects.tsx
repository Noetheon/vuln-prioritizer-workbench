import { createFileRoute } from "@/lib/router"

import { ProjectsRoute } from "../../workbench/routes/ProjectsRoute"

export const Route = createFileRoute("/_layout/projects")({
  component: ProjectsRoute,
})
