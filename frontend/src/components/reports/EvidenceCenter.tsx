import {
  AlertTriangle,
  Clock,
  Download,
  FileText,
  Globe,
  History,
  Layers,
  ShieldCheck,
} from "lucide-react"
import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  ProviderStatusPublic,
  ReportPublic,
  ReportVerificationPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwDemoBanner,
  VpwEmptyState,
  VpwEvidenceArtifactCard,
  VpwEvidenceManifestCard,
  VpwExecutiveDecisionSummary,
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPageContainer,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "@/components/vpw"
import {
  DEMO_PROJECT,
  DEMO_REPORTS,
  DEMO_RUNS,
  DEMO_SUMMARY,
} from "@/lib/demo-data"
import { formatProviderFreshness } from "@/lib/provider-format"
import {
  formatReportDateTime,
  type ReportFormat,
  reportFormatLabel,
  reportSizeLabel,
} from "@/lib/report-format"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import { runStatusLabel } from "@/lib/risk-format"
import {
  ARTIFACT_CARDS,
  priorityCount,
  reportFormatTone,
  runBadgeTone,
  runFileLabel,
  runMetricTone,
  statusBannerTone,
  summaryOpenFindings,
  verificationSummary,
} from "./evidence-center-model"

export type EvidenceCenterProps = {
  selectedProject: ProjectPublic | null
  selectedRunId: string
  onRunIdChange: (id: string) => void
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  projectRuns: AnalysisRunPublic[]
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

type RunContextProps = {
  selectedProject: ProjectPublic | null
  selectedRunId: string
  onRunIdChange: (id: string) => void
  selectedReportRun: AnalysisRunPublic | null
  projectRuns: AnalysisRunPublic[]
  runsLoading: boolean
  reportActionsEnabled: boolean
  isDemo: boolean
}

function RunContext({
  isDemo,
  onRunIdChange,
  projectRuns,
  reportActionsEnabled,
  runsLoading,
  selectedProject,
  selectedReportRun,
  selectedRunId,
}: RunContextProps) {
  const runLabel = isDemo
    ? "Succeeded"
    : selectedReportRun
      ? runStatusLabel(selectedReportRun.status)
      : runsLoading
        ? "Loading"
        : "No run selected"
  const runDetail = isDemo
    ? "demo-run-0001"
    : selectedReportRun
      ? `${runFileLabel(selectedReportRun)} · ${selectedReportRun.id.slice(0, 8)}`
      : "Select a completed run"
  const readinessTone: VpwBadgeTone =
    reportActionsEnabled || isDemo ? "success" : "neutral"

  return (
    <VpwSection>
      <VpwSectionHeader
        actions={
          isDemo ? <VpwBadge tone="warning">Demo preview</VpwBadge> : null
        }
        description="Generate audit-ready vulnerability evidence, executive summaries, and technical exports."
        eyebrow="Reports"
        title="Evidence Center"
      />
      {isDemo ? (
        <VpwDemoBanner>
          <strong>Demo preview.</strong> Sample evidence data is visible only
          because no real project is selected. Connect a project and completed
          run to generate production evidence.
        </VpwDemoBanner>
      ) : null}
      <VpwToolbar label="Report context">
        <VpwToolbarGroup>
          <div className="min-w-0">
            <p className="vpw-label">Project</p>
            <p className="truncate text-sm font-semibold text-[var(--vpw-text-primary)]">
              {isDemo
                ? DEMO_PROJECT.name
                : (selectedProject?.name ?? "None selected")}
            </p>
          </div>
          <div className="min-w-0">
            <p className="vpw-label">Analysis run</p>
            <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2">
              <VpwBadge
                tone={
                  isDemo || selectedReportRun
                    ? runBadgeTone((selectedReportRun ?? DEMO_RUNS[0]).status)
                    : "neutral"
                }
              >
                {runLabel}
              </VpwBadge>
              <span className="min-w-0 truncate text-xs text-[var(--vpw-text-secondary)]">
                {runDetail}
              </span>
            </div>
          </div>
        </VpwToolbarGroup>
        <VpwToolbarGroup>
          {!isDemo ? (
            <Select
              disabled={runsLoading || projectRuns.length === 0}
              onValueChange={onRunIdChange}
              value={selectedRunId}
            >
              <SelectTrigger
                aria-label="Select analysis run"
                className="h-9 min-w-64 max-w-full"
              >
                <SelectValue placeholder="Select analysis run" />
              </SelectTrigger>
              <SelectContent>
                {projectRuns.length === 0 ? (
                  <SelectItem disabled value="none">
                    No runs available
                  </SelectItem>
                ) : null}
                {projectRuns.map((run) => (
                  <SelectItem key={run.id} value={run.id}>
                    {`${runStatusLabel(run.status)} - ${runFileLabel(run)} - ${run.id.slice(0, 8)}`}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : null}
          <VpwBadge tone={readinessTone}>
            <ShieldCheck aria-hidden="true" className="h-3 w-3" />
            {reportActionsEnabled
              ? "Ready for generation"
              : isDemo
                ? "Demo mode"
                : "Select completed run"}
          </VpwBadge>
        </VpwToolbarGroup>
      </VpwToolbar>
    </VpwSection>
  )
}

type SummaryProps = {
  projectSummary: ProjectDecisionSummaryPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  reports: ReportPublic[]
  selectedReportRun: AnalysisRunPublic | null
  providerStatus: ProviderStatusPublic | null
  isDemo: boolean
  reportsLoading: boolean
}

function EvidenceSummary({
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
    : selectedRunSummary ?? projectSummary
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

function ActionStatus({ error, message }: { error: string; message: string }) {
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

function ArtifactSection({
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

type HistoryProps = {
  reports: ReportPublic[]
  reportsLoading: boolean
  isDemo: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
  verificationLoading: boolean
  onDownload: (report: ReportPublic) => void
  onVerify: (report: ReportPublic) => void
}

function ReportHistory({
  isDemo,
  onDownload,
  onVerify,
  reports,
  reportsLoading,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: HistoryProps) {
  const rows = isDemo ? DEMO_REPORTS : reports
  const verifiedTargetId = verificationReportTarget?.id ?? ""
  const verifiedSummary = verificationSummary(verificationReport)
  const columns: VpwDataTableColumn<ReportPublic>[] = [
    {
      id: "artifact",
      header: "Artifact",
      cell: (report) => (
        <div className="min-w-0">
          <div className="flex min-w-0 items-center gap-2">
            <span className="truncate font-mono text-xs font-medium">
              {report.filename}
            </span>
            {isDemo ? <VpwBadge tone="warning">Demo</VpwBadge> : null}
          </div>
          <p className="mt-1 text-xs text-[var(--vpw-text-secondary)]">
            {reportSizeLabel(report.size_bytes)}
          </p>
        </div>
      ),
      className: "min-w-52",
    },
    {
      id: "format",
      header: "Format",
      cell: (report) => (
        <VpwBadge tone={reportFormatTone(report.format)}>
          {reportFormatLabel(report.format)}
        </VpwBadge>
      ),
    },
    {
      id: "generated",
      header: "Generated",
      cell: (report) => (
        <span className="text-sm text-[var(--vpw-text-secondary)]">
          {formatReportDateTime(report.created_at)}
        </span>
      ),
    },
    {
      id: "checksum",
      header: "Checksum",
      cell: (report) => {
        const realChecksum = !report.sha256.startsWith("demo-only")
        const checksum = realChecksum
          ? `${report.sha256.slice(0, 12)}...`
          : "Demo preview"
        return (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="cursor-default font-mono text-xs text-[var(--vpw-text-secondary)]">
                  {checksum}
                </span>
              </TooltipTrigger>
              <TooltipContent>
                {realChecksum
                  ? report.sha256
                  : "Demo preview - not a real checksum"}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )
      },
    },
    {
      id: "status",
      header: "Status",
      cell: (report) => {
        const isVerificationTarget = verifiedTargetId === report.id
        const verificationOk = isVerificationTarget && verifiedSummary.ok === true
        const verificationFailed = Boolean(
          isVerificationTarget && verificationReport && verifiedSummary.ok !== true,
        )
        const verificationInProgress =
          isVerificationTarget && verificationLoading
        return (
          <VpwBadge
            tone={
              isDemo
                ? "warning"
                : verificationFailed
                  ? "critical"
                  : verificationOk
                    ? "success"
                    : verificationInProgress
                      ? "info"
                      : "success"
            }
          >
            {isDemo
              ? "Demo"
              : verificationInProgress
                ? "Verifying"
                : verificationOk
                  ? "Verified"
                  : verificationFailed
                    ? "Verify failed"
                    : report.format === "zip"
                      ? "Bundle"
                      : "Generated"}
          </VpwBadge>
        )
      },
    },
    {
      id: "actions",
      header: "Actions",
      headerClassName: "text-right",
      className: "text-right",
      cell: (report) => (
        <div className="flex items-center justify-end gap-2">
          {report.format === "zip" && !isDemo ? (
            <Button
              aria-label={`Verify ${report.filename}`}
              aria-busy={
                verificationLoading && verificationReportTarget?.id === report.id
              }
              disabled={
                verificationLoading && verificationReportTarget?.id === report.id
              }
              onClick={() => onVerify(report)}
              size="icon"
              type="button"
              variant="ghost"
            >
              <ShieldCheck aria-hidden="true" className="h-4 w-4" />
            </Button>
          ) : null}
          <Button
            aria-label={`Download ${report.filename}`}
            disabled={isDemo}
            onClick={() => !isDemo && onDownload(report)}
            size="sm"
            type="button"
            variant="outline"
          >
            <Download aria-hidden="true" className="h-4 w-4" />
            Download
          </Button>
        </div>
      ),
    },
  ]

  if (reportsLoading && !isDemo) {
    return (
      <VpwPanel className="min-h-80">
        <div className="mb-4 flex items-center gap-2">
          <History aria-hidden="true" className="h-4 w-4" />
          <h3 className="font-semibold text-[var(--vpw-text-primary)]">
            Report History
          </h3>
        </div>
        <div className="space-y-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-3/4" />
        </div>
      </VpwPanel>
    )
  }

  return (
    <VpwPanel className="min-h-80 min-w-0 overflow-hidden p-0">
      <div className="border-b border-[var(--vpw-border-subtle)] p-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="vpw-label">Generated artifacts</p>
            <h3 className="mt-1 text-lg font-semibold text-[var(--vpw-text-primary)]">
              Report History
            </h3>
          </div>
          <History
            aria-hidden="true"
            className="h-4 w-4 text-[var(--vpw-text-muted)]"
          />
        </div>
      </div>
      <VpwDataTable
        caption="Report history list"
        className="overflow-x-auto"
        columns={columns}
        data={rows}
        density="compact"
        emptyState={
          <VpwEmptyState
            description="Use the artifact cards above to generate the first report for this run."
            icon={<FileText aria-hidden="true" className="h-5 w-5" />}
            title="No reports generated yet"
          />
        }
        getRowKey={(report) => report.id}
      />
    </VpwPanel>
  )
}

type ManifestProps = {
  selectedProject: ProjectPublic | null
  selectedReportRun: AnalysisRunPublic | null
  reports: ReportPublic[]
  providerStatus: ProviderStatusPublic | null
  isDemo: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
  verificationLoading: boolean
  onDownload: (report: ReportPublic) => void
}

function ManifestPreview({
  isDemo,
  onDownload,
  providerStatus,
  reports,
  selectedProject,
  selectedReportRun,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: ManifestProps) {
  const project = isDemo ? DEMO_PROJECT : selectedProject
  const run = isDemo ? DEMO_RUNS[0] : selectedReportRun
  const effectiveReports = isDemo ? DEMO_REPORTS : reports
  const zipReport = effectiveReports.find((report) => report.format === "zip")
  const providerSources =
    providerStatus?.snapshot.selected_sources?.join(", ") ??
    (isDemo ? "nvd, epss, kev" : "Unavailable")
  const checksumStatus = isDemo
    ? "Demo preview - not real checksums"
    : zipReport?.sha256
      ? zipReport.sha256
      : "Not generated yet"
  const matchesVerifiedBundle =
    Boolean(zipReport) && verificationReportTarget?.id === zipReport?.id
  const verifiedSummary = matchesVerifiedBundle
    ? verificationSummary(verificationReport)
    : {}
  const verifiedFiles = Number(verifiedSummary.verified_files ?? 0)
  const modifiedFiles = Number(verifiedSummary.modified_files ?? 0)
  const missingFiles = Number(verifiedSummary.missing_files ?? 0)
  const verificationStatus = isDemo
    ? "Demo preview"
    : matchesVerifiedBundle && verificationLoading
      ? "Verification running"
      : matchesVerifiedBundle && verificationReport && verifiedSummary.ok === true
        ? `Verified - ${verifiedFiles} files matched`
        : matchesVerifiedBundle && verificationReport
          ? `Verification failed - ${modifiedFiles} modified, ${missingFiles} missing`
          : zipReport
            ? "Ready for verification"
            : "Not generated yet"

  return (
    <VpwEvidenceManifestCard
      checksumStatus={checksumStatus}
      className="h-full"
      demo={isDemo}
      downloadDisabled={isDemo || !zipReport}
      downloadLabel={
        isDemo
          ? "Demo manifest"
          : zipReport
            ? "Download evidence bundle"
            : "Generate ZIP first"
      }
      files={effectiveReports.map((report) => ({
        label: reportFormatLabel(report.format),
        path: report.filename,
      }))}
      generatedAt={
        zipReport
          ? formatReportDateTime(zipReport.created_at)
          : "Not generated yet"
      }
      onDownload={
        !isDemo && zipReport ? () => onDownload(zipReport) : undefined
      }
      project={project?.name ?? "None selected"}
      providerSources={providerSources}
      runId={run ? run.id : "Not selected"}
      verificationStatus={verificationStatus}
    />
  )
}

type DecisionProps = {
  projectSummary: ProjectDecisionSummaryPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  selectedReportRun: AnalysisRunPublic | null
  isDemo: boolean
}

function ExecutiveDecision({
  isDemo,
  projectSummary,
  selectedReportRun,
  selectedRunSummary,
}: DecisionProps) {
  const effectiveSummary = isDemo
    ? DEMO_SUMMARY
    : selectedRunSummary ?? projectSummary
  const critical = priorityCount(effectiveSummary, "critical")
  const high = priorityCount(effectiveSummary, "high")
  const kevHits = effectiveSummary?.kev_hits ?? 0
  const totalFindings = effectiveSummary?.finding_count ?? 0
  const openFindings = summaryOpenFindings(effectiveSummary)
  const problem =
    totalFindings > 0
      ? `${critical + high} critical/high findings across ${totalFindings} total; ${kevHits} are known-exploited KEV entries.`
      : "No findings data available for this run."
  const businessImpact =
    critical > 0
      ? `${critical} critical CVEs carry active exploitation risk across exposed services.`
      : "No critical vulnerabilities detected. Confirm posture through high-severity review."
  const recommendation =
    critical + high > 0
      ? "Patch critical findings within 48 hours and high-severity findings within 7 days. Prioritize KEV entries first."
      : "Maintain the standard remediation cadence and re-run after the next deployment cycle."
  const priority = critical > 0 ? "Immediate" : high > 0 ? "High" : "Routine"
  const priorityTone: VpwBadgeTone =
    critical > 0 ? "critical" : high > 0 ? "warning" : "success"
  const decisionStatement = isDemo
    ? "Demo preview - connect a real project and run to generate evidence-backed decision language."
    : openFindings > 0
      ? `${openFindings} open findings require remediation owner assignment. Evidence artifacts for run ${selectedReportRun?.id.slice(0, 8) ?? "N.A."} are available for audit review.`
      : "All findings are resolved or waived. Keep the evidence bundle for compliance archive."

  return (
    <VpwExecutiveDecisionSummary
      businessImpact={businessImpact}
      decisionStatement={decisionStatement}
      demo={isDemo}
      priority={priority}
      priorityTone={priorityTone}
      problem={problem}
      recommendation={recommendation}
    />
  )
}

function QualityFacts({
  isDemo,
  providerStatus,
  reports,
}: {
  isDemo: boolean
  providerStatus: ProviderStatusPublic | null
  reports: ReportPublic[]
}) {
  const providerSummary = providerStatus
    ? formatProviderFreshness(providerStatus)
    : null
  const effectiveReports = isDemo ? DEMO_REPORTS : reports
  const bundle = effectiveReports.find((report) => report.format === "zip")

  return (
    <VpwKeyValueList
      columns={2}
      items={[
        {
          label: "Provider snapshot",
          value: isDemo
            ? "Demo sources"
            : (providerSummary?.value ?? "Unavailable"),
          description: isDemo
            ? "NVD, EPSS, and KEV sample context"
            : (providerSummary?.detail ?? "No provider status available"),
          tone: isDemo || providerStatus?.status === "ok" ? "success" : "info",
        },
        {
          label: "Bundle checksum",
          value: bundle ? "Recorded" : "Not generated",
          description: bundle
            ? bundle.sha256
            : "Generate an evidence ZIP to record bundle integrity.",
          tone: bundle ? "success" : "neutral",
        },
      ]}
    />
  )
}

export function EvidenceCenter({
  activeReportFormat,
  onCreateReport,
  onDownloadReport,
  onRunIdChange,
  onVerifyReport,
  projectRuns,
  projectSummary,
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
  selectedReportRun,
  selectedRunId,
  selectedRunSummary,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: EvidenceCenterProps) {
  const isDemo = DEMO_MODE_ENABLED && !selectedProject
  const combinedError = [
    runsError,
    runDetailError,
    reportsError,
    reportActionError,
  ]
    .filter(Boolean)
    .join(" ")

  return (
    <VpwPageContainer className="space-y-8 px-0 py-0">
      <RunContext
        isDemo={isDemo}
        onRunIdChange={onRunIdChange}
        projectRuns={projectRuns}
        reportActionsEnabled={reportActionsEnabled}
        runsLoading={runsLoading}
        selectedProject={selectedProject}
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
