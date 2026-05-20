import { Link } from "@/lib/router"
import { AlertTriangle, ArrowUp, Eye, FileDown, Upload } from "lucide-react"
import type { ReactNode } from "react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  VpwPanel,
  VpwSection,
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
  icon: ReactNode
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
      <VpwPanel className="findings-triage-overview" padded={false}>
        <div className="findings-triage-overview__header">
          <div>
            <p className="vpw-label text-[var(--vpw-teal)]">
              Remediation workspace
            </p>
            <h2>Findings queue</h2>
            <p>
              Prioritized vulnerability findings for {projectName}. Review
              owner-ready evidence, context, and remediation state.
            </p>
          </div>
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
        </div>
        <dl className="findings-triage-strip" aria-label="Queue signal summary">
          {metrics.map((metric) => (
            <div data-tone={metric.tone} key={metric.label}>
              <dt>
                <span className="findings-triage-strip__icon">
                  {metric.icon}
                </span>
                {metric.label}
              </dt>
              <dd>{metric.value}</dd>
              <p>{metric.description}</p>
            </div>
          ))}
        </dl>
      </VpwPanel>
    </VpwSection>
  )
}
