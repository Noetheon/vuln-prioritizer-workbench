import { AlertTriangle, Clock, Globe, Layers, ShieldCheck } from "lucide-react"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProviderStatusPublic,
  ReportPublic,
} from "@/api-client"
import {
  VpwCompactMetric,
  VpwMetricStrip,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import { DEMO_REPORTS, DEMO_RUNS, DEMO_SUMMARY } from "@/lib/demo-data"
import { runStatusLabel } from "@/lib/risk-format"
import {
  evidenceBundleReport,
  generatedArtifactsDetail,
  priorityCount,
  runMetricTone,
} from "./evidence-center-model"

type SummaryProps = {
  projectSummary: ProjectDecisionSummaryPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  reports: ReportPublic[]
  selectedReportRun: AnalysisRunPublic | null
  providerStatus: ProviderStatusPublic | null
  isDemo: boolean
  reportsLoading: boolean
}

export function EvidenceSummary({
  isDemo,
  projectSummary,
  reports,
  reportsLoading,
  selectedReportRun,
  selectedRunSummary,
}: SummaryProps) {
  const effectiveSummary = isDemo
    ? DEMO_SUMMARY
    : (selectedRunSummary ?? projectSummary)
  const effectiveRun = isDemo ? DEMO_RUNS[0] : selectedReportRun
  const effectiveReports = isDemo ? DEMO_REPORTS : reports
  const critical = priorityCount(effectiveSummary, "critical")
  const high = priorityCount(effectiveSummary, "high")
  const criticalHigh = critical + high
  const zipReport = evidenceBundleReport(effectiveReports)
  const reportCount =
    reportsLoading && !isDemo ? "..." : String(effectiveReports.length)

  return (
    <VpwSection>
      <VpwSectionHeader
        description="Run status, finding scope, bundle availability, and generated artifacts."
        title="Evidence summary"
      />
      <VpwMetricStrip minCardWidth="11.5rem">
        <VpwCompactMetric
          description={
            isDemo
              ? "demo run 2025-04-30"
              : effectiveRun
                ? `Run ${effectiveRun.id.slice(0, 8)}`
                : "No run selected"
          }
          icon={<Clock aria-hidden="true" className="h-4 w-4" />}
          label="Run status"
          tone={runMetricTone(effectiveRun, isDemo)}
          value={
            isDemo
              ? "Succeeded"
              : effectiveRun
                ? runStatusLabel(effectiveRun.status)
                : "No run"
          }
        />
        <VpwCompactMetric
          description="Across all priorities"
          icon={<Layers aria-hidden="true" className="h-4 w-4" />}
          label="Findings in scope"
          tone="info"
          value={String(effectiveSummary?.finding_count ?? 0)}
        />
        <VpwCompactMetric
          description={`${critical} critical - ${high} high`}
          icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
          label="Critical + High"
          tone={
            criticalHigh > 0
              ? critical > 0
                ? "critical"
                : "warning"
              : "neutral"
          }
          value={String(criticalHigh)}
        />
        <VpwCompactMetric
          description={zipReport ? "Evidence ZIP exists" : "Not built"}
          icon={<ShieldCheck aria-hidden="true" className="h-4 w-4" />}
          label="Evidence bundle"
          tone={zipReport ? "success" : "neutral"}
          value={zipReport ? "Available" : "Not built"}
        />
        <VpwCompactMetric
          description={generatedArtifactsDetail(effectiveReports)}
          icon={<Globe aria-hidden="true" className="h-4 w-4" />}
          label="Generated artifacts"
          tone={effectiveReports.length > 0 ? "success" : "neutral"}
          value={reportCount}
        />
      </VpwMetricStrip>
    </VpwSection>
  )
}
