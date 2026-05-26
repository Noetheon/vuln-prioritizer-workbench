import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "@/api-client"
import { useState } from "react"
import type { ReportFormat } from "@/lib/report-format"
import { VpwPageStack } from "@/components/vpw"
import { ActionStatus, RunContext } from "./EvidenceCenterSections"
import { EvidenceCenterTabs } from "./EvidenceCenterTabs"
import { EvidenceGenerateDrawer } from "./EvidenceGenerateDrawer"

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
  const [generateDrawerOpen, setGenerateDrawerOpen] = useState(false)
  const combinedError = [
    projectListError,
    runsError,
    runDetailError,
    reportsError,
    reportActionError,
  ]
    .filter(Boolean)
    .join(" ")
  const hasDecisionContext = selectedReportRun !== null

  return (
    <VpwPageStack className="evidence-center">
      <RunContext
        onOpenGenerateDrawer={() => setGenerateDrawerOpen(true)}
        onProjectChange={onProjectChange}
        onRunIdChange={onRunIdChange}
        providerStatus={providerStatus}
        projectRuns={projectRuns}
        projects={projects}
        projectListLoading={projectListLoading}
        reportActionsEnabled={reportActionsEnabled}
        runsLoading={runsLoading}
        selectedProject={selectedProject}
        selectedProjectId={selectedProjectId}
        selectedReportRun={selectedReportRun}
        selectedRunId={selectedRunId}
        selectedRunSummary={selectedRunSummary}
      />

      <ActionStatus error={combinedError} message={reportActionMessage} />

      <EvidenceCenterTabs
        activeReportFormat={activeReportFormat}
        hasDecisionContext={hasDecisionContext}
        onCreateReport={onCreateReport}
        onDownloadReport={onDownloadReport}
        onOpenGenerateDrawer={() => setGenerateDrawerOpen(true)}
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
      <EvidenceGenerateDrawer
        activeReportFormat={activeReportFormat}
        onCreateReport={onCreateReport}
        onOpenChange={setGenerateDrawerOpen}
        open={generateDrawerOpen}
        project={selectedProject}
        providerStatus={providerStatus}
        reportActionsEnabled={reportActionsEnabled}
        reports={reports}
        selectedReportRun={selectedReportRun}
        selectedRunSummary={selectedRunSummary}
      />
    </VpwPageStack>
  )
}
