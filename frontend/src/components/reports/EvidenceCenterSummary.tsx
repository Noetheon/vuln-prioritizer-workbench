import { AlertTriangle, Clock, Globe, Layers, ShieldCheck } from "lucide-react"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProviderStatusPublic,
  ReportPublic,
} from "@/api-client"
import {
  VpwBadge,
  VpwEvidenceArtifactCard,
  VpwGrid,
  VpwMetricCard,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { DEMO_REPORTS, DEMO_RUNS, DEMO_SUMMARY } from "@/lib/demo-data"
import { formatProviderFreshness } from "@/lib/provider-format"
import type { ReportFormat } from "@/lib/report-format"
import { runStatusLabel } from "@/lib/risk-format"
import {
  ARTIFACT_CARDS,
  priorityCount,
  runMetricTone,
  statusBannerTone,
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
  providerStatus,
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
  const zipReport = effectiveReports.find((report) => report.format === "zip")
  const providerSummary = providerStatus
    ? formatProviderFreshness(providerStatus)
    : null
  const reportCount =
    reportsLoading && !isDemo ? "..." : String(effectiveReports.length)

  return (
    <VpwSection>
      <VpwSectionHeader
        description="Evidence readiness for the selected run."
        title="Evidence Summary"
      />
      <VpwGrid columns={4} className="xl:grid-cols-5">
        <VpwMetricCard
          description={
            isDemo
              ? "demo run 2025-04-30"
              : effectiveRun
                ? `Run ${effectiveRun.id.slice(0, 8)}`
                : "No run selected"
          }
          icon={<Clock aria-hidden="true" className="h-4 w-4" />}
          label="Selected run"
          tone={runMetricTone(effectiveRun, isDemo)}
          value={
            isDemo
              ? "Succeeded"
              : effectiveRun
                ? runStatusLabel(effectiveRun.status)
                : "No run"
          }
        />
        <VpwMetricCard
          description="Across all priorities"
          icon={<Layers aria-hidden="true" className="h-4 w-4" />}
          label="Findings in scope"
          tone="info"
          value={String(effectiveSummary?.finding_count ?? 0)}
        />
        <VpwMetricCard
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
        <VpwMetricCard
          description={
            zipReport ? "Evidence bundle available" : "Generate ZIP to finalize"
          }
          icon={<ShieldCheck aria-hidden="true" className="h-4 w-4" />}
          label="Evidence bundle"
          tone={zipReport ? "success" : "neutral"}
          value={zipReport ? "Ready" : "Open"}
        />
        <VpwMetricCard
          description={
            isDemo
              ? "NVD, EPSS, KEV"
              : (providerSummary?.detail ?? "Provider snapshot unavailable")
          }
          icon={<Globe aria-hidden="true" className="h-4 w-4" />}
          label="Artifacts"
          tone={isDemo || providerStatus?.status === "ok" ? "success" : "info"}
          value={reportCount}
        />
      </VpwGrid>
    </VpwSection>
  )
}

export function ActionStatus({
  error,
  message,
}: {
  error: string
  message: string
}) {
  if (!error && !message) return null

  return (
    <div className="space-y-3">
      {error ? (
        <VpwStatusBanner title="Report action failed" tone="critical">
          {error}
        </VpwStatusBanner>
      ) : null}
      {message ? (
        <VpwStatusBanner
          title="Report action complete"
          tone={statusBannerTone(message)}
        >
          {message}
        </VpwStatusBanner>
      ) : null}
    </div>
  )
}

type ArtifactSectionProps = {
  activeReportFormat: string
  isDemo: boolean
  reportActionsEnabled: boolean
  onCreateReport: (format: ReportFormat) => Promise<void>
}

export function ArtifactSection({
  activeReportFormat,
  isDemo,
  onCreateReport,
  reportActionsEnabled,
}: ArtifactSectionProps) {
  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          isDemo ? (
            <VpwBadge tone="warning">Generation disabled</VpwBadge>
          ) : null
        }
        description={
          reportActionsEnabled
            ? "Select a format to generate an artifact for the selected run."
            : isDemo
              ? "Demo artifacts are preview-only. Connect a real completed run to enable generation."
              : "Select a completed run to enable generation."
        }
        title="Generate Evidence Artifacts"
      />
      <VpwGrid columns={4}>
        {ARTIFACT_CARDS.map((card) => {
          const Icon = card.icon
          const isActive = activeReportFormat === card.reportFormat
          return (
            <VpwEvidenceArtifactCard
              actionLabel={isActive ? "Generating..." : card.actionLabel}
              audience={card.audience}
              busy={isActive}
              description={card.description}
              disabled={!reportActionsEnabled || isActive}
              format={card.format}
              icon={<Icon aria-hidden="true" className="h-4 w-4" />}
              key={card.reportFormat}
              onAction={() => void onCreateReport(card.reportFormat)}
              title={card.title}
            />
          )
        })}
      </VpwGrid>
    </VpwSection>
  )
}
