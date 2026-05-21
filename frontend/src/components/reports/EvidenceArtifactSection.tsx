import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ReportPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  CountBadge,
  StatusLozenge,
  VpwBadge,
  VpwGrid,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
} from "@/components/vpw"
import type { ReportFormat } from "@/lib/report-format"
import {
  ADDITIONAL_ARTIFACT_FORMATS,
  RECOMMENDED_ARTIFACT_FORMATS,
  artifactCardForFormat,
  artifactStatusLabel,
  attackNavigatorAvailable,
  generatedActionLabel,
  reportForFormat,
} from "./evidence-center-model"

type ArtifactSectionProps = {
  activeReportFormat: string
  isDemo: boolean
  reportActionsEnabled: boolean
  reports: ReportPublic[]
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  onOpenGenerateDrawer: () => void
  onVerifyReport: (report: ReportPublic) => Promise<void>
}

export function ArtifactSection({
  activeReportFormat,
  isDemo,
  onCreateReport,
  onDownloadReport,
  onOpenGenerateDrawer,
  onVerifyReport,
  reportActionsEnabled,
  reports,
  selectedReportRun,
  selectedRunSummary,
}: ArtifactSectionProps) {
  return (
    <VpwSection id="evidence-artifacts">
      <VpwSectionHeader
        actions={
          <Button
            disabled={!reportActionsEnabled}
            onClick={onOpenGenerateDrawer}
            type="button"
          >
            Generate evidence
          </Button>
        }
        description={
          reportActionsEnabled
            ? "Recommended artifacts first; additional exports stay compact."
            : isDemo
              ? "Demo artifacts are preview-only. Connect a real completed run to enable generation."
              : "Select a completed run to enable generation."
        }
        title="Recommended artifacts"
      />
      <VpwGrid columns={3}>
        {RECOMMENDED_ARTIFACT_FORMATS.map((format) => (
          <RecommendedArtifactCard
            activeReportFormat={activeReportFormat}
            format={format}
            key={format}
            onCreateReport={onCreateReport}
            onDownloadReport={onDownloadReport}
            onVerifyReport={onVerifyReport}
            report={reportForFormat(reports, format)}
            reportActionsEnabled={reportActionsEnabled}
          />
        ))}
      </VpwGrid>
      <AdditionalExports
        activeReportFormat={activeReportFormat}
        attackAvailable={attackNavigatorAvailable(
          selectedRunSummary,
          selectedReportRun,
        )}
        onCreateReport={onCreateReport}
        onDownloadReport={onDownloadReport}
        reportActionsEnabled={reportActionsEnabled}
        reports={reports}
      />
    </VpwSection>
  )
}

function RecommendedArtifactCard({
  activeReportFormat,
  format,
  onCreateReport,
  onDownloadReport,
  onVerifyReport,
  report,
  reportActionsEnabled,
}: {
  activeReportFormat: string
  format: ReportFormat
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  onVerifyReport: (report: ReportPublic) => Promise<void>
  report: ReportPublic | null
  reportActionsEnabled: boolean
}) {
  const card = artifactCardForFormat(format)
  const Icon = card.icon
  const generating = activeReportFormat === format

  return (
    <VpwPanel className="flex h-full flex-col gap-4 p-4">
      <div className="flex items-start gap-3">
        <div className="rounded-[var(--vpw-radius-md)] bg-[var(--vpw-bg-panel)] p-2 text-[var(--vpw-text-secondary)]">
          <Icon aria-hidden="true" className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="text-base font-semibold text-[var(--vpw-text-primary)]">
            {card.title}
          </h3>
          <p className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
            {card.description}
          </p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <VpwBadge>{card.format}</VpwBadge>
        <StatusLozenge
          density="compact"
          label={artifactStatusLabel(report)}
          status={report ? "succeeded" : "unknown"}
        />
      </div>
      <ArtifactActions
        className="mt-auto"
        format={format}
        generating={generating}
        onCreateReport={onCreateReport}
        onDownloadReport={onDownloadReport}
        onVerifyReport={onVerifyReport}
        report={report}
        reportActionsEnabled={reportActionsEnabled}
      />
    </VpwPanel>
  )
}

function ArtifactActions({
  className,
  disabledByContext = false,
  format,
  generateVariant = "default",
  generating,
  onCreateReport,
  onDownloadReport,
  onVerifyReport,
  report,
  reportActionsEnabled,
}: {
  className?: string
  disabledByContext?: boolean
  format: ReportFormat
  generateVariant?: "default" | "outline"
  generating: boolean
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  onVerifyReport?: (report: ReportPublic) => Promise<void>
  report: ReportPublic | null
  reportActionsEnabled: boolean
}) {
  return (
    <div className={`flex flex-wrap gap-2 ${className ?? ""}`}>
      <Button
        aria-busy={generating}
        disabled={!reportActionsEnabled || generating || disabledByContext}
        onClick={() => void onCreateReport(format)}
        size="sm"
        type="button"
        variant={generateVariant}
      >
        {generating ? "Generating" : generatedActionLabel(format, report)}
      </Button>
      {report ? (
        <Button
          onClick={() => void onDownloadReport(report)}
          size="sm"
          type="button"
          variant="outline"
        >
          Download
        </Button>
      ) : null}
      {onVerifyReport && report?.format === "zip" ? (
        <Button
          onClick={() => void onVerifyReport(report)}
          size="sm"
          type="button"
          variant="outline"
        >
          Verify bundle
        </Button>
      ) : null}
    </div>
  )
}

function AdditionalExports({
  activeReportFormat,
  attackAvailable,
  onCreateReport,
  onDownloadReport,
  reportActionsEnabled,
  reports,
}: {
  activeReportFormat: string
  attackAvailable: boolean
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  reportActionsEnabled: boolean
  reports: ReportPublic[]
}) {
  return (
    <VpwPanel className="flex flex-col gap-3 p-4">
      <VpwSectionHeader
        description="Compact exports for spreadsheets, automation, CI, and defensive ATT&CK review."
        eyebrow="Additional exports"
        title="Additional exports"
      />
      <div className="grid gap-2">
        {ADDITIONAL_ARTIFACT_FORMATS.map((format) => {
          const card = artifactCardForFormat(format)
          const report = reportForFormat(reports, format)
          const disabledByContext = format === "attack-navigator" && !attackAvailable
          const generating = activeReportFormat === format
          return (
            <div
              className="grid gap-3 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-3 md:grid-cols-[minmax(0,1fr)_auto_auto] md:items-center"
              key={format}
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <strong className="text-sm text-[var(--vpw-text-primary)]">
                    {card.title}
                  </strong>
                  <CountBadge label={card.format} value={card.format} />
                </div>
                <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
                  {disabledByContext
                    ? "Available only when mapped defensive ATT&CK context exists."
                    : card.description}
                </p>
              </div>
              <StatusLozenge
                density="compact"
                label={artifactStatusLabel(report)}
                status={report ? "succeeded" : "unknown"}
              />
              <ArtifactActions
                className="justify-start md:justify-end"
                disabledByContext={disabledByContext}
                format={format}
                generateVariant="outline"
                generating={generating}
                onCreateReport={onCreateReport}
                onDownloadReport={onDownloadReport}
                report={report}
                reportActionsEnabled={reportActionsEnabled}
              />
            </div>
          )
        })}
      </div>
    </VpwPanel>
  )
}
