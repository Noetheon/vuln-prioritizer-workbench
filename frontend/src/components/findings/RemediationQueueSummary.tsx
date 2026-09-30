import { Link } from "@/lib/router"
import { AlertTriangle, ArrowUp, Clock, FileDown, Upload } from "lucide-react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwCommandPanel,
  MetricStrip,
  type MetricStripMetric,
  VpwSection,
} from "@/components/vpw"

type RemediationQueueSummaryProps = {
  criticalCount: number
  displayProject: ProjectPublic | null
  highCount: number
  kevCount: number
  overdueCount: number
  // "open-work": the default view; "filtered": the active filters narrow it.
  scope: "filtered" | "open-work"
}

export function RemediationQueueSummary({
  criticalCount,
  displayProject,
  highCount,
  kevCount,
  overdueCount,
  scope,
}: RemediationQueueSummaryProps) {
  const projectSearch = selectedProjectRouteSearch(displayProject?.id ?? "")
  const projectName = displayProject?.name ?? "the selected project"
  const inView = scope === "filtered" ? "matching the filters" : "open work"
  const metrics: MetricStripMetric[] = [
    {
      description: `Critical, ${inView}`,
      icon: <AlertTriangle aria-hidden="true" className="h-4 w-4" />,
      label: "Critical",
      tone: "critical",
      value: criticalCount,
    },
    {
      description: `High, ${inView}`,
      icon: <ArrowUp aria-hidden="true" className="h-4 w-4" />,
      label: "High",
      tone: "warning",
      value: highCount,
    },
    {
      description: `Known exploited, ${inView}`,
      icon: <AlertTriangle aria-hidden="true" className="h-4 w-4" />,
      label: "KEV",
      tone: "support",
      value: kevCount,
    },
    {
      description: `Past SLA, ${inView}`,
      icon: <Clock aria-hidden="true" className="h-4 w-4" />,
      label: "Overdue",
      tone: overdueCount > 0 ? "critical" : "info",
      value: overdueCount,
    },
  ]

  return (
    <VpwSection>
      <VpwCommandPanel
        actions={
          <div className="findings-triage-overview__actions">
            <Button asChild size="sm" variant="outline">
              <Link search={projectSearch} to="/reports">
                <FileDown aria-hidden="true" className="mr-1.5" size={14} />
                Generate evidence
              </Link>
            </Button>
            <Button asChild size="sm">
              <Link search={projectSearch} to="/imports">
                <Upload aria-hidden="true" className="mr-1.5" size={14} />
                Import findings
              </Link>
            </Button>
          </div>
        }
        className="findings-triage-overview"
        description={`Prioritized vulnerability findings for ${projectName}. Review owner-ready evidence, context, and remediation state.`}
        eyebrow="Remediation workspace"
        title="Findings queue"
      >
        <MetricStrip
          aria-label="Queue signal summary"
          metrics={metrics}
          minCardWidth="10.75rem"
        />
      </VpwCommandPanel>
    </VpwSection>
  )
}
