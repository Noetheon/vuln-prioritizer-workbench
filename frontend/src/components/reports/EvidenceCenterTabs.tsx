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
  hasDecisionContext: boolean | AnalysisRunPublic | null
  isDemo: boolean
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
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
  isDemo,
  onCreateReport,
  onDownloadReport,
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
  return (
    <Tabs className="flex flex-col gap-4" defaultValue="artifacts">
      <TabsList
        aria-label="Evidence Center sections"
        className="flex h-auto flex-wrap justify-start gap-2 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-panel)] p-1"
      >
        <TabsTrigger value="artifacts">Artifacts</TabsTrigger>
        <TabsTrigger value="decision">Decision Summary</TabsTrigger>
        <TabsTrigger value="manifest">Manifest & Verification</TabsTrigger>
        <TabsTrigger value="history">History</TabsTrigger>
        <TabsTrigger value="quality">Data Quality</TabsTrigger>
      </TabsList>

      <TabsContent className="mt-0 flex flex-col gap-4" value="artifacts">
        <ArtifactSection
          activeReportFormat={activeReportFormat}
          isDemo={isDemo}
          onCreateReport={onCreateReport}
          reportActionsEnabled={reportActionsEnabled}
        />
        <ReportHistory
          emptyDescription="Generate an artifact above to populate this run's artifact table."
          isDemo={isDemo}
          onDownload={onDownloadReport}
          onVerify={onVerifyReport}
          panelDescription="Generated report artifacts for the selected run."
          panelEyebrow="Artifact inventory"
          panelTitle="Generated Artifacts"
          reports={reports}
          reportsLoading={reportsLoading}
          verificationLoading={verificationLoading}
          verificationReport={verificationReport}
          verificationReportTarget={verificationReportTarget}
        />
      </TabsContent>

      <TabsContent className="mt-0" value="decision">
        <VpwSection>
          <VpwSectionHeader
            actions={
              isDemo ? <VpwBadge tone="warning">Demo language</VpwBadge> : null
            }
            description="Decision-ready wording derived from the selected run summary."
            title="Executive Decision"
          />
          {hasDecisionContext ? (
            <ExecutiveDecision
              isDemo={isDemo}
              projectSummary={projectSummary}
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
          isDemo={isDemo}
          reportActionsEnabled={reportActionsEnabled}
          reports={reports}
          reportsLoading={reportsLoading}
          selectedReportRun={selectedReportRun}
          verificationLoading={verificationLoading}
          verificationReport={verificationReport}
          verificationReportTarget={verificationReportTarget}
        />
        <ManifestPreview
          isDemo={isDemo}
          onDownload={onDownloadReport}
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
          isDemo={isDemo}
          onDownload={onDownloadReport}
          onVerify={onVerifyReport}
          panelDescription="Previously generated reports for the selected run."
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
            isDemo={isDemo}
            providerStatus={providerStatus}
            reports={reports}
            selectedRunSummary={selectedRunSummary}
          />
        </VpwSection>
      </TabsContent>
    </Tabs>
  )
}
