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
import {
  type ArtifactCard,
  additionalArtifactCards,
  recommendedArtifactCards,
} from "@/lib/report-capability-catalog"
import type { ReportFormat } from "@/lib/report-format"
import {
  artifactStatusLabel,
  attackNavigatorAvailable,
  reportForFormat,
} from "./evidence-center-model"
import { ArtifactActions } from "./EvidenceArtifactActions"

type ArtifactSectionProps = {
  activeReportFormat: string
  reportActionsEnabled: boolean
  reports: ReportPublic[]
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  onOpenGenerateDrawer: () => void
  onVerifyReport: (report: ReportPublic) => Promise<void>
  artifactCards: readonly ArtifactCard[]
}

export function ArtifactSection({
  activeReportFormat,
  onCreateReport,
  onDownloadReport,
  onOpenGenerateDrawer,
  onVerifyReport,
  artifactCards,
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
            : "Select a completed run to enable generation."
        }
        title="Recommended artifacts"
      />
      <VpwGrid className="evidence-artifact-action-grid" columns={3}>
        {recommendedArtifactCards(artifactCards).map((card) => (
          <RecommendedArtifactCard
            activeReportFormat={activeReportFormat}
            card={card}
            key={card.reportFormat}
            onCreateReport={onCreateReport}
            onDownloadReport={onDownloadReport}
            onVerifyReport={onVerifyReport}
            report={reportForFormat(reports, card.reportFormat)}
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
        artifactCards={artifactCards}
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
  card,
  onCreateReport,
  onDownloadReport,
  onVerifyReport,
  report,
  reportActionsEnabled,
}: {
  activeReportFormat: string
  card: ArtifactCard
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  onVerifyReport: (report: ReportPublic) => Promise<void>
  report: ReportPublic | null
  reportActionsEnabled: boolean
}) {
  const Icon = card.icon
  const format = card.reportFormat
  const generating = activeReportFormat === format

  return (
    <VpwPanel className="evidence-artifact-card flex h-full flex-col gap-4 p-4">
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
        card={card}
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

function AdditionalExports({
  activeReportFormat,
  artifactCards,
  attackAvailable,
  onCreateReport,
  onDownloadReport,
  reportActionsEnabled,
  reports,
}: {
  activeReportFormat: string
  artifactCards: readonly ArtifactCard[]
  attackAvailable: boolean
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  reportActionsEnabled: boolean
  reports: ReportPublic[]
}) {
  return (
    <VpwPanel className="evidence-additional-exports flex flex-col gap-3 p-4">
      <VpwSectionHeader
        description="Compact exports for spreadsheets, automation, CI, and defensive ATT&CK review."
        eyebrow="Additional exports"
        title="Additional exports"
      />
      <div className="grid gap-2">
        {additionalArtifactCards(artifactCards).map((card) => {
          const format = card.reportFormat
          const report = reportForFormat(reports, format)
          const disabledByContext =
            format === "attack-navigator" && !attackAvailable
          const generating = activeReportFormat === format
          return (
            <div
              className="evidence-additional-export-row grid gap-3 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-3 md:grid-cols-[minmax(0,1fr)_auto_auto] md:items-center"
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
                card={card}
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
