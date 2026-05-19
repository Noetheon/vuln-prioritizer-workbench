import { Link } from "@/lib/router"
import { Eye, FileSearch, ListChecks } from "lucide-react"
import type { ReactNode } from "react"
import type { AnalysisRunPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"

function ImportRunAction({
  children,
  label,
}: {
  children: ReactNode
  label: string
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

export function ImportRunActions({
  onOpenDiagnostics,
  run,
}: {
  onOpenDiagnostics: (runId: string) => void
  run: AnalysisRunPublic
}) {
  return (
    <div className="vpw-table-actions">
      <ImportRunAction label="View details">
        <Button
          asChild
          className="vpw-table-action-button"
          size="icon-sm"
          variant="outline"
        >
          <Link
            aria-label={`View details for run ${run.id.slice(0, 8)}`}
            params={{ runId: run.id }}
            search={{ projectId: run.project_id }}
            to="/imports/runs/$runId"
          >
            <Eye aria-hidden="true" />
          </Link>
        </Button>
      </ImportRunAction>
      <ImportRunAction label="View diagnostics">
        <Button
          aria-label={`View diagnostics for run ${run.id.slice(0, 8)}`}
          className="vpw-table-action-button"
          onClick={() => onOpenDiagnostics(run.id)}
          size="icon-sm"
          type="button"
          variant="outline"
        >
          <FileSearch aria-hidden="true" />
        </Button>
      </ImportRunAction>
      <ImportRunAction label="Review findings">
        <Button
          asChild
          className="vpw-table-action-button"
          size="icon-sm"
          variant="outline"
        >
          <Link
            aria-label={`Review findings for run ${run.id.slice(0, 8)}`}
            search={{ projectId: run.project_id }}
            to="/findings"
          >
            <ListChecks aria-hidden="true" />
          </Link>
        </Button>
      </ImportRunAction>
    </div>
  )
}
