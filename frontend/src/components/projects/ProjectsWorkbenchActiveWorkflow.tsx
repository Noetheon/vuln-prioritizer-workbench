import {
  BarChart3,
  FileCheck2,
  FileInput,
  ListChecks,
} from "lucide-react"
import { Link } from "@/lib/router"
import type { ProjectUrlSearch } from "@/workbench/selected-project-search"

type ActiveProjectWorkflowLinksProps = {
  projectSearch: ProjectUrlSearch
}

const WORKFLOW_LINKS = [
  {
    detail: "Load supplied evidence",
    icon: FileInput,
    label: "Import",
    to: "/imports",
  },
  {
    detail: "Prioritize findings",
    icon: ListChecks,
    label: "Triage",
    to: "/findings",
  },
  {
    detail: "Generate artifacts",
    icon: FileCheck2,
    label: "Evidence",
    to: "/reports",
  },
  {
    detail: "Review posture",
    icon: BarChart3,
    label: "Overview",
    to: "/",
  },
] as const

export function ActiveProjectWorkflowLinks({
  projectSearch,
}: ActiveProjectWorkflowLinksProps) {
  return (
    <nav aria-label="Active project workflow" className="projects-workflow-links">
      {WORKFLOW_LINKS.map(({ detail, icon: Icon, label, to }) => (
        <Link
          className="projects-workflow-link"
          key={to}
          search={projectSearch}
          to={to}
        >
          <Icon aria-hidden="true" />
          <span>
            <strong>{label}</strong>
            <small>{detail}</small>
          </span>
        </Link>
      ))}
    </nav>
  )
}
