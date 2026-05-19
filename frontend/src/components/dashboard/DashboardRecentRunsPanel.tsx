import { Link } from "@/lib/router"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import type { DashboardRunFact } from "./dashboard-model"

type DashboardRecentRunsPanelProps = {
  latestRunFactsRows: readonly DashboardRunFact[]
  selectedProjectId: string
}

export function DashboardRecentRunsPanel({
  latestRunFactsRows,
  selectedProjectId,
}: DashboardRecentRunsPanelProps) {
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)

  return (
    <VpwSurface className="gap-3 py-4">
      <VpwSurfaceHeader className="px-4 pb-0">
        <div className="flex items-center justify-between gap-3">
          <VpwSurfaceTitle className="text-sm">Recent Runs</VpwSurfaceTitle>
          <Button asChild size="sm" variant="outline">
            <Link search={projectSearch} to="/imports">
              View all
            </Link>
          </Button>
        </div>
      </VpwSurfaceHeader>
      <VpwSurfaceBody className="px-4">
        {latestRunFactsRows.length === 0 ? (
          <p className="text-xs text-muted-foreground">No analysis runs yet.</p>
        ) : (
          <div className="flex flex-col gap-2">
            {latestRunFactsRows.map((run) => (
              <div
                className="flex items-center justify-between gap-2 rounded-md border bg-muted/20 px-2.5 py-2 text-xs"
                key={run.id}
              >
                <VpwBadge className="shrink-0" tone={runBadgeTone(run.tone)}>
                  {run.status}
                </VpwBadge>
                <span className="truncate text-muted-foreground">
                  {run.startedAt}
                </span>
              </div>
            ))}
          </div>
        )}
      </VpwSurfaceBody>
    </VpwSurface>
  )
}

function runBadgeTone(tone: DashboardRunFact["tone"]): VpwBadgeTone {
  if (tone === "succeeded") return "success"
  if (tone === "failed") return "critical"
  if (tone === "warning") return "warning"
  return "neutral"
}
