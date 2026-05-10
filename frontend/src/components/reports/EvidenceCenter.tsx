import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "@/api-client"
import { VpwBadge, VpwPageContainer, VpwSection, VpwSectionHeader } from "@/components/vpw"
import type { ReportFormat } from "@/lib/report-format"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import {
  ActionStatus,
  ArtifactSection,
  EvidenceSummary,
  ExecutiveDecision,
  ManifestPreview,
  QualityFacts,
  ReportHistory,
  RunContext,
} from "./EvidenceCenterSections"

export type EvidenceCenterProps = {
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  projects: ProjectPublic[]
  projectListLoading: boolean
  onProjectChange: (id: string) => void
  selectedRunId: string
  onRunIdChange: (id: string) => void
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  projectRuns: AnalysisRunPublic[]
  projectListError: string
  runsLoading: boolean
  runsError: string
  runDetailError: string
  reports: ReportPublic[]
  reportsLoading: boolean
  reportsError: string
  projectSummary: ProjectDecisionSummaryPublic | null
  providerStatus: ProviderStatusPublic | null
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
  verificationLoading: boolean
  reportActionsEnabled: boolean
  activeReportFormat: string
  reportActionError: string
  reportActionMessage: string
  onCreateReport: (format: ReportFormat) => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  onVerifyReport: (report: ReportPublic) => Promise<void>
}

export function EvidenceCenter({
  activeReportFormat,
  onCreateReport,
  onDownloadReport,
  onProjectChange,
  onRunIdChange,
  onVerifyReport,
  projectListError,
  projectListLoading,
  projectRuns,
  projectSummary,
  projects,
  providerStatus,
  reportActionError,
  reportActionMessage,
  reportActionsEnabled,
  reports,
  reportsError,
  reportsLoading,
  runDetailError,
  runsError,
  runsLoading,
  selectedProject,
  selectedProjectId,
  selectedReportRun,
  selectedRunId,
  selectedRunSummary,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: EvidenceCenterProps) {
  const combinedError = [
    projectListError,
    runsError,
    runDetailError,
    reportsError,
    reportActionError,
  ]
    .filter(Boolean)
    .join(" ")
  const isDemo = DEMO_MODE_ENABLED && !selectedProject && !combinedError

  return (
    <VpwPageContainer className="space-y-6 px-0 py-0">
      <RunContext
        isDemo={isDemo}
        onProjectChange={onProjectChange}
        onRunIdChange={onRunIdChange}
        projectRuns={projectRuns}
        projects={projects}
        projectListLoading={projectListLoading}
        reportActionsEnabled={reportActionsEnabled}
        runsLoading={runsLoading}
        selectedProject={selectedProject}
        selectedProjectId={selectedProjectId}
        selectedReportRun={selectedReportRun}
        selectedRunId={selectedRunId}
      />

      <EvidenceSummary
        isDemo={isDemo}
        projectSummary={projectSummary}
        providerStatus={providerStatus}
        reports={reports}
        reportsLoading={reportsLoading}
        selectedReportRun={selectedReportRun}
        selectedRunSummary={selectedRunSummary}
      />

      <ActionStatus error={combinedError} message={reportActionMessage} />

      <ArtifactSection
        activeReportFormat={activeReportFormat}
        isDemo={isDemo}
        onCreateReport={onCreateReport}
        reportActionsEnabled={reportActionsEnabled}
      />

      <VpwSection>
        <VpwSectionHeader
          description="Generated reports and manifest metadata remain connected to the selected run."
          title="Report History and Evidence Manifest"
        />
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(22rem,0.65fr)]">
          <ReportHistory
            isDemo={isDemo}
            onDownload={onDownloadReport}
            onVerify={onVerifyReport}
            reports={reports}
            reportsLoading={reportsLoading}
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
        </div>
      </VpwSection>

      {isDemo || selectedReportRun ? (
        <VpwSection>
          <VpwSectionHeader
            actions={
              isDemo ? <VpwBadge tone="warning">Demo language</VpwBadge> : null
            }
            description="Decision-ready wording derived from the selected run summary."
            title="Executive Decision"
          />
          <ExecutiveDecision
            isDemo={isDemo}
            projectSummary={projectSummary}
            selectedReportRun={selectedReportRun}
            selectedRunSummary={selectedRunSummary}
          />
        </VpwSection>
      ) : null}

      <VpwSection>
        <VpwSectionHeader
          description="Operational evidence metadata for audit review."
          title="Evidence Quality"
        />
        <QualityFacts
          isDemo={isDemo}
          providerStatus={providerStatus}
          reports={reports}
        />
      </VpwSection>
    </VpwPageContainer>
  )
}
