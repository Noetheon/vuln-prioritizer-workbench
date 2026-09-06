import type { ReactNode } from "react"
import type { RiskReductionOpportunityPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Link } from "@/lib/router"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"

/** Keep a remediation group's exact finding identities when opening its work. */
export function DashboardOpportunityScope({
  children,
  className,
  opportunity,
  selectedProjectId,
}: {
  children: ReactNode
  className?: string
  opportunity: RiskReductionOpportunityPublic
  selectedProjectId: string
}) {
  const findingIds = opportunity.finding_ids ?? []
  const search = selectedProjectRouteSearch(selectedProjectId)
  if (findingIds.length === 1) {
    return (
      <Link
        className={className}
        params={{ findingId: findingIds[0] }}
        search={search}
        to="/findings/$findingId"
      >
        {children}
      </Link>
    )
  }
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button className={className} size="sm" variant="link">
          {children}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{opportunity.label}</DialogTitle>
          <DialogDescription>
            {opportunity.recommended_action}
          </DialogDescription>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          {findingIds.length} finding{findingIds.length === 1 ? "" : "s"} in
          this component and action scope.
        </p>
        <ul className="grid max-h-72 gap-2 overflow-y-auto">
          {findingIds.map((findingId) => (
            <li key={findingId}>
              <Link
                className="text-sm underline underline-offset-4"
                params={{ findingId }}
                search={search}
                to="/findings/$findingId"
              >
                {opportunity.cve_id} · {opportunity.component ?? "Finding"} ·{" "}
                {findingId.slice(0, 8)}
              </Link>
            </li>
          ))}
        </ul>
        {findingIds.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Exact finding scope is unavailable. Refresh the dashboard to load
            current evidence.
          </p>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
