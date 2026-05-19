import { Link } from "@/lib/router"
import {
  CalendarClock,
  ChevronRight,
  FileArchive,
  FileCheck2,
  ListChecks,
  type LucideIcon,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  type VpwBadgeTone,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"

type DashboardRecommendedActionsPanelProps = {
  selectedProjectId: string
}

const RECOMMENDED_ACTIONS: readonly {
  icon: LucideIcon
  label: string
  to: "/" | "/findings" | "/waivers" | "/reports" | "/imports"
  tone: VpwBadgeTone
}[] = [
  {
    icon: ListChecks,
    label: "Review critical items in Triage",
    to: "/findings",
    tone: "critical",
  },
  {
    icon: FileCheck2,
    label: "Accept or document risk",
    to: "/waivers",
    tone: "success",
  },
  {
    icon: FileArchive,
    label: "Generate evidence bundle",
    to: "/reports",
    tone: "support",
  },
  {
    icon: CalendarClock,
    label: "Schedule next analysis",
    to: "/imports",
    tone: "info",
  },
]

export function DashboardRecommendedActionsPanel({
  selectedProjectId,
}: DashboardRecommendedActionsPanelProps) {
  const projectSearch = selectedProjectRouteSearch(selectedProjectId)

  return (
    <VpwSurface className="gap-3 py-4">
      <VpwSurfaceHeader className="px-4 pb-0">
        <VpwSurfaceTitle className="text-sm">
          Recommended Next Actions
        </VpwSurfaceTitle>
      </VpwSurfaceHeader>
      <VpwSurfaceBody className="px-4">
        <nav aria-label="Recommended dashboard actions">
          <ul className="flex flex-col gap-1">
            {RECOMMENDED_ACTIONS.map((action) => {
              const Icon = action.icon
              return (
                <li key={action.label}>
                  <Button
                    asChild
                    className="dashboard-next-action"
                    variant="ghost"
                  >
                    <Link search={projectSearch} to={action.to}>
                      <span
                        className={`dashboard-next-action-icon dashboard-next-action-icon--${action.tone}`}
                      >
                        <Icon aria-hidden="true" className="size-3.5" />
                      </span>
                      <span className="min-w-0 flex-1 truncate text-left">
                        {action.label}
                      </span>
                      <ChevronRight
                        aria-hidden="true"
                        className="size-3.5 shrink-0 text-[var(--vpw-text-muted)]"
                      />
                    </Link>
                  </Button>
                </li>
              )
            })}
          </ul>
        </nav>
      </VpwSurfaceBody>
    </VpwSurface>
  )
}
