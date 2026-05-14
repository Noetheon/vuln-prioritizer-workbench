import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "@/api-client"
import type { ReportFormat } from "@/lib/report-format"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import {
  ActionStatus,
  EvidenceSummary,
  RunContext,
} from "./EvidenceCenterSections"
import { EvidenceCenterTabs } from "./EvidenceCenterTabs"

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
  const hasDecisionContext = isDemo || selectedReportRun

  return (
    <div className="flex flex-col gap-6">
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

      <EvidenceCenterTabs
        activeReportFormat={activeReportFormat}
        hasDecisionContext={hasDecisionContext}
        isDemo={isDemo}
        onCreateReport={onCreateReport}
        onDownloadReport={onDownloadReport}
        onVerifyReport={onVerifyReport}
        projectSummary={projectSummary}
        providerStatus={providerStatus}
        reportActionsEnabled={reportActionsEnabled}
        reports={reports}
        reportsLoading={reportsLoading}
        selectedProject={selectedProject}
        selectedReportRun={selectedReportRun}
        selectedRunSummary={selectedRunSummary}
        verificationLoading={verificationLoading}
        verificationReport={verificationReport}
        verificationReportTarget={verificationReportTarget}
      />
    </div>
  )
}
