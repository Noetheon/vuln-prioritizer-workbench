import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "@/api-client"
import {
  VpwBadge,
  VpwEmptyState,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import type { ReportFormat } from "@/lib/report-format"
import {
  ArtifactSection,
  EvidenceLifecycle,
  ExecutiveDecision,
  ManifestPreview,
  QualityFacts,
  ReportHistory,
} from "./EvidenceCenterSections"

type EvidenceCenterTabsProps = {
  activeReportFormat: string
  hasDecisionContext: boolean
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  onOpenGenerateDrawer: () => void
  onVerifyReport: (report: ReportPublic) => Promise<void>
  projectSummary: ProjectDecisionSummaryPublic | null
  providerStatus: ProviderStatusPublic | null
  reportActionsEnabled: boolean
  reports: ReportPublic[]
  reportsLoading: boolean
  selectedProject: ProjectPublic | null
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  verificationLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
}

export function EvidenceCenterTabs({
  activeReportFormat,
  hasDecisionContext,
  onCreateReport,
  onDownloadReport,
  onOpenGenerateDrawer,
  onVerifyReport,
  projectSummary,
  providerStatus,
  reportActionsEnabled,
  reports,
  reportsLoading,
  selectedProject,
  selectedReportRun,
  selectedRunSummary,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: EvidenceCenterTabsProps) {
  const hasArtifacts = reports.length > 0
  const runFailed = selectedReportRun?.status === "failed"

  return (
    <Tabs
      className="evidence-tabs flex flex-col gap-4"
      defaultValue="artifacts"
    >
      <TabsList
        aria-label="Evidence Center sections"
        className="evidence-tabs-list flex h-auto flex-wrap justify-start gap-2 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] p-1"
      >
        <TabsTrigger value="artifacts">Artifacts</TabsTrigger>
        <TabsTrigger value="decision">Decision Summary</TabsTrigger>
        <TabsTrigger value="manifest">Manifest & Verification</TabsTrigger>
        <TabsTrigger value="history">History</TabsTrigger>
        <TabsTrigger value="quality">Data Quality</TabsTrigger>
      </TabsList>

      <TabsContent className="mt-0 flex flex-col gap-4" value="artifacts">
        {!selectedReportRun ? (
          <VpwEmptyState
            action={<VpwBadge tone="neutral">Select run</VpwBadge>}
            description="Select a completed import run to generate evidence artifacts."
            title="No import run selected"
          />
        ) : null}
        {runFailed ? (
          <VpwStatusBanner title="Run failed" tone="critical">
            The selected run did not complete. Parser output and run diagnostics
            are available from the Imports route before evidence can be
            generated.
          </VpwStatusBanner>
        ) : null}
        {hasArtifacts ? (
          <ReportHistory
            emptyDescription="No artifacts generated yet. Generate an executive report, technical report, or evidence bundle for this run."
            mode="inventory"
            onDownload={onDownloadReport}
            onVerify={onVerifyReport}
            panelDescription="What exists now and what can be downloaded or verified."
            panelEyebrow="Artifact inventory"
            panelTitle="Generated artifacts"
            reports={reports}
            reportsLoading={reportsLoading}
            verificationLoading={verificationLoading}
            verificationReport={verificationReport}
            verificationReportTarget={verificationReportTarget}
          />
        ) : null}
        <ArtifactSection
          activeReportFormat={activeReportFormat}
          onCreateReport={onCreateReport}
          onDownloadReport={onDownloadReport}
          onOpenGenerateDrawer={onOpenGenerateDrawer}
          onVerifyReport={onVerifyReport}
          reportActionsEnabled={reportActionsEnabled}
          reports={reports}
          selectedReportRun={selectedReportRun}
          selectedRunSummary={selectedRunSummary}
        />
        {!hasArtifacts ? (
          <ReportHistory
            emptyDescription="Generate an executive report, technical report, or evidence bundle for this run."
            mode="inventory"
            onDownload={onDownloadReport}
            onVerify={onVerifyReport}
            panelDescription="What exists now and what can be downloaded or verified."
            panelEyebrow="Artifact inventory"
            panelTitle="Generated artifacts"
            reports={reports}
            reportsLoading={reportsLoading}
            verificationLoading={verificationLoading}
            verificationReport={verificationReport}
            verificationReportTarget={verificationReportTarget}
          />
        ) : null}
      </TabsContent>

      <TabsContent className="mt-0" value="decision">
        <VpwSection>
          <VpwSectionHeader
            description="Decision-ready wording derived from the selected run summary."
            title="Executive Decision"
          />
          {hasDecisionContext ? (
            <ExecutiveDecision
              onCreateReport={onCreateReport}
              onDownloadReport={onDownloadReport}
              projectSummary={projectSummary}
              reports={reports}
              selectedProject={selectedProject}
              selectedReportRun={selectedReportRun}
              selectedRunSummary={selectedRunSummary}
            />
          ) : (
            <VpwEmptyState
              description="Select a completed run to populate executive decision language."
              title="No decision context selected"
            />
          )}
        </VpwSection>
      </TabsContent>

      <TabsContent className="mt-0 flex flex-col gap-4" value="manifest">
        <EvidenceLifecycle
          activeReportFormat={activeReportFormat}
          reportActionsEnabled={reportActionsEnabled}
          reports={reports}
          reportsLoading={reportsLoading}
          selectedReportRun={selectedReportRun}
          verificationLoading={verificationLoading}
          verificationReport={verificationReport}
          verificationReportTarget={verificationReportTarget}
        />
        <ManifestPreview
          onDownload={onDownloadReport}
          onVerify={onVerifyReport}
          providerStatus={providerStatus}
          reports={reports}
          selectedProject={selectedProject}
          selectedReportRun={selectedReportRun}
          verificationLoading={verificationLoading}
          verificationReport={verificationReport}
          verificationReportTarget={verificationReportTarget}
        />
      </TabsContent>

      <TabsContent className="mt-0" value="history">
        <ReportHistory
          mode="history"
          onDownload={onDownloadReport}
          onVerify={onVerifyReport}
          panelDescription="Previously generated reports for the selected run."
          panelEyebrow="Generated artifact history"
          panelTitle="Generated artifact history"
          reports={reports}
          reportsLoading={reportsLoading}
          verificationLoading={verificationLoading}
          verificationReport={verificationReport}
          verificationReportTarget={verificationReportTarget}
        />
      </TabsContent>

      <TabsContent className="mt-0" value="quality">
        <VpwSection>
          <VpwSectionHeader
            description="Operational evidence metadata for audit review."
            title="Data Quality"
          />
          <QualityFacts
            providerStatus={providerStatus}
            reports={reports}
            selectedReportRun={selectedReportRun}
            selectedRunSummary={selectedRunSummary}
            verificationLoading={verificationLoading}
            verificationReport={verificationReport}
            verificationReportTarget={verificationReportTarget}
          />
        </VpwSection>
      </TabsContent>
    </Tabs>
  )
}
