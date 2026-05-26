import { Link } from "@/lib/router"
import { AlertTriangle, ArrowUp, Eye, FileDown, Upload } from "lucide-react"
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
  openCount: number
}

export function RemediationQueueSummary({
  criticalCount,
  displayProject,
  highCount,
  kevCount,
  openCount,
}: RemediationQueueSummaryProps) {
  const projectSearch = selectedProjectRouteSearch(displayProject?.id ?? "")
  const projectName = displayProject?.name ?? "the selected project"
  const metrics: MetricStripMetric[] = [
    {
      description: "Immediate owner attention",
      icon: <AlertTriangle aria-hidden="true" className="h-4 w-4" />,
      label: "Critical",
      tone: "critical",
      value: criticalCount,
    },
    {
      description: "Near-term remediation",
      icon: <ArrowUp aria-hidden="true" className="h-4 w-4" />,
      label: "High",
      tone: "warning",
      value: highCount,
    },
    {
      description: "Known exploited",
      icon: <AlertTriangle aria-hidden="true" className="h-4 w-4" />,
      label: "KEV",
      tone: "support",
      value: kevCount,
    },
    {
      description: "Open lifecycle",
      icon: <Eye aria-hidden="true" className="h-4 w-4" />,
      label: "Open",
      tone: "info",
      value: openCount,
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
