import { Link } from "@tanstack/react-router"
import { AlertTriangle, ArrowUp, Eye, FileDown, Upload } from "lucide-react"
import type { ProjectPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  VpwBadge,
  VpwDemoBanner,
  VpwGrid,
  VpwMetricCard,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"

export function DemoBanner() {
  return (
    <VpwDemoBanner>
      <strong className="font-semibold">Demo preview</strong> - showing sample
      findings. Connect a real project to see live data.
    </VpwDemoBanner>
  )
}

type SummaryChipProps = {
  compact?: boolean
  label: string
  value: number | string
  tone?: "critical" | "warning" | "info" | "support"
}

function SummaryChip({
  compact = false,
  label,
  value,
  tone = "info",
}: SummaryChipProps) {
  return (
    <VpwBadge
      className={
        compact
          ? "min-h-9 w-full justify-between gap-2 px-3 text-[0.72rem]"
          : undefined
      }
      tone={tone}
    >
      {label}: <span className="font-bold">{value}</span>
    </VpwBadge>
  )
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
  return (
    <VpwSection>
      <VpwPanel className="flex flex-col gap-5 bg-[var(--vpw-bg-card)]">
        <VpwSectionHeader
          actions={
            <>
              <Button asChild size="sm" variant="outline">
                <Link to="/reports">
                  <FileDown aria-hidden="true" className="mr-1.5" size={14} />
                  Generate evidence
                </Link>
              </Button>
              <Button asChild size="sm">
                <Link to="/imports">
                  <Upload aria-hidden="true" className="mr-1.5" size={14} />
                  Import findings
                </Link>
              </Button>
            </>
          }
          description={
            displayProject?.name
              ? `Prioritized remediation queue for ${displayProject.name}`
              : "Prioritized remediation queue for the selected project"
          }
          eyebrow="Remediation Queue"
          title="Findings"
        />
        <fieldset className="m-0 grid grid-cols-2 gap-2 border-0 p-0 sm:hidden">
          <legend className="sr-only">Queue signal summary</legend>
          <SummaryChip
            compact
            label="Critical"
            tone="critical"
            value={criticalCount}
          />
          <SummaryChip compact label="High" tone="warning" value={highCount} />
          <SummaryChip compact label="KEV" tone="support" value={kevCount} />
          <SummaryChip compact label="Open" tone="info" value={openCount} />
        </fieldset>
        <VpwGrid className="hidden sm:grid" columns={4}>
          <VpwMetricCard
            description="highest urgency"
            icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
            label="Critical"
            tone="critical"
            value={criticalCount}
          />
          <VpwMetricCard
            description="near-term action"
            icon={<ArrowUp aria-hidden="true" className="h-4 w-4" />}
            label="High"
            tone="warning"
            value={highCount}
          />
          <VpwMetricCard
            description="known exploited"
            icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
            label="KEV"
            tone="support"
            value={kevCount}
          />
          <VpwMetricCard
            description="open lifecycle"
            icon={<Eye aria-hidden="true" className="h-4 w-4" />}
            label="Open"
            tone="info"
            value={openCount}
          />
        </VpwGrid>
        <div className="hidden flex-wrap gap-2 sm:flex">
          <SummaryChip label="Critical" tone="critical" value={criticalCount} />
          <SummaryChip label="High" tone="warning" value={highCount} />
          <SummaryChip label="KEV" tone="support" value={kevCount} />
          <SummaryChip label="Open" tone="info" value={openCount} />
        </div>
      </VpwPanel>
    </VpwSection>
  )
}
