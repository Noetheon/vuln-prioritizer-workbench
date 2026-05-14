import type {
  AnalysisRunPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "@/api-client"
import {
  VpwBadge,
  VpwEvidenceArtifactCard,
  VpwEvidenceFlowCard,
  VpwGrid,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { DEMO_REPORTS } from "@/lib/demo-data"
import type { ReportFormat } from "@/lib/report-format"
import {
  ARTIFACT_CARDS,
  statusBannerTone,
  verificationSummary,
} from "./evidence-center-model"

export function ActionStatus({
  error,
  message,
}: {
  error: string
  message: string
}) {
  if (!error && !message) return null

  return (
    <div className="flex flex-col gap-3">
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

type EvidenceLifecycleProps = {
  activeReportFormat: string
  isDemo: boolean
  reportActionsEnabled: boolean
  reports: ReportPublic[]
  reportsLoading: boolean
  selectedReportRun: AnalysisRunPublic | null
  verificationLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
}

export function EvidenceLifecycle({
  activeReportFormat,
  isDemo,
  reportActionsEnabled,
  reports,
  reportsLoading,
  selectedReportRun,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: EvidenceLifecycleProps) {
  const effectiveReports = isDemo ? DEMO_REPORTS : reports
  const zipReport = effectiveReports.find((report) => report.format === "zip")
  const verifiedTargetId = verificationReportTarget?.id ?? ""
  const zipVerificationSelected = Boolean(
    zipReport && verifiedTargetId === zipReport.id,
  )
  const verifiedSummary = zipVerificationSelected
    ? verificationSummary(verificationReport)
    : {}
  const verificationOk = zipVerificationSelected && verifiedSummary.ok === true
  const verificationFailed = Boolean(
    zipVerificationSelected &&
      verificationReport &&
      verifiedSummary.ok !== true,
  )
  const selectedRunMeta = isDemo
    ? "Demo run"
    : selectedReportRun
      ? `Run ${selectedReportRun.id.slice(0, 8)}`
      : "Waiting"
  const artifactMeta = activeReportFormat
    ? "Generating"
    : reportsLoading && !isDemo
      ? "Loading"
      : effectiveReports.length > 0
        ? `${effectiveReports.length} generated`
        : reportActionsEnabled
          ? "Ready"
          : "Waiting"
  const verificationMeta = verificationLoading
    ? "Verifying"
    : verificationOk
      ? "Verified"
      : verificationFailed
        ? "Failed"
        : zipReport
          ? "Ready"
          : "Waiting"

  return (
    <VpwSection>
      <VpwSectionHeader
        description="Track the report path from run context through artifact generation and bundle verification."
        title="Evidence Lifecycle"
      />
      <VpwEvidenceFlowCard
        items={[
          {
            description: isDemo
              ? "Demo context is loaded for preview only."
              : selectedReportRun
                ? "A run is selected and can anchor generated artifacts."
                : "Select a completed run before generating evidence.",
            meta: selectedRunMeta,
            title: "Select run context",
            tone: isDemo || selectedReportRun ? "success" : "neutral",
          },
          {
            description: activeReportFormat
              ? "A report artifact is being generated."
              : effectiveReports.length > 0
                ? "Generated artifacts are available in report history."
                : "Choose a format once a completed run is selected.",
            meta: artifactMeta,
            title: "Generate artifacts",
            tone:
              activeReportFormat || reportActionsEnabled
                ? effectiveReports.length > 0
                  ? "success"
                  : "warning"
                : "neutral",
          },
          {
            description: verificationOk
              ? "The evidence bundle manifest matched the generated files."
              : verificationFailed
                ? "The latest verification found bundle drift."
                : zipReport
                  ? "Verify the ZIP bundle before using it as audit evidence."
                  : "Generate an evidence ZIP to enable bundle verification.",
            meta: verificationMeta,
            title: "Verify and archive bundle",
            tone: verificationFailed
              ? "critical"
              : verificationOk
                ? "success"
                : zipReport || verificationLoading
                  ? "warning"
                  : "neutral",
          },
        ]}
      />
    </VpwSection>
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
    <VpwSection id="evidence-artifacts">
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
