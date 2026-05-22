import { Link } from "@/lib/router"
import { FileDown, Upload } from "lucide-react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  ContextBar,
  MetricStrip,
  VpwDemoBanner,
} from "@/components/vpw"

export function DemoBanner() {
  return (
    <VpwDemoBanner>
      <strong className="font-semibold">Demo preview</strong> - showing sample
      findings. Connect a real project to see live data.
    </VpwDemoBanner>
  )
}

type SummaryMetric = {
  description: string
  label: string
  tone: "critical" | "warning" | "support" | "info"
  value: number
}

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
  const metrics: SummaryMetric[] = [
    {
      description: "Immediate owner attention",
      label: "Critical",
      tone: "critical",
      value: criticalCount,
    },
    {
      description: "Near-term remediation",
      label: "High",
      tone: "warning",
      value: highCount,
    },
    {
      description: "Known exploited",
      label: "KEV",
      tone: "critical",
      value: kevCount,
    },
    {
      description: "Open lifecycle",
      label: "Open",
      tone: "info",
      value: openCount,
    },
  ]

  return (
    <>
      <ContextBar
        actions={
          <>
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
          </>
        }
        description={`Prioritized findings for ${projectName}. Work from owner attention, evidence strength, affected asset context, and lifecycle state.`}
        items={[
          { label: "Project", value: projectName },
          { label: "Primary object", value: "Prioritized findings" },
          { label: "Decision basis", value: "Supplied evidence and provider signals" },
          { label: "Next action", value: "Open queue row or quick view" },
        ]}
        title="Triage context"
      />
      <MetricStrip metrics={metrics} />
    </>
  )
}
