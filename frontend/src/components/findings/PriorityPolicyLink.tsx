import type { ReactNode } from "react"
import { Link } from "@/lib/router"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"

/** Links an SLA or priority explanation to the project's priority policy. */
export function PriorityPolicyLink({
  children,
  projectId,
}: {
  children: ReactNode
  projectId: string
}) {
  return (
    <Link
      className="underline decoration-dotted underline-offset-2 hover:text-[var(--vpw-text-primary)]"
      search={selectedProjectRouteSearch(projectId)}
      title="Thresholds and SLA targets come from the project's priority policy"
      to="/policy"
    >
      {children}
    </Link>
  )
}
