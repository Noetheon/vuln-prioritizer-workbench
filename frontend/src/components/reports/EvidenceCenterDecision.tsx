import { Link } from "@/lib/router"
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
  type VpwBadgeTone,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  artifactVerificationLabel,
  contextCoverageFacts,
  evidenceBundleReport,
  priorityCount,
  providerSnapshotShortId,
  reportForFormat,
  summaryOpenFindings,
} from "./evidence-center-model"

type DecisionProps = {
  projectSummary: ProjectDecisionSummaryPublic | null
  selectedProject: ProjectPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  selectedReportRun: AnalysisRunPublic | null
  reports: ReportPublic[]
  onCreateReport: (format: "html" | "zip") => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
}

export function ExecutiveDecision({
  onCreateReport,
  onDownloadReport,
  projectSummary,
  reports,
  selectedProject,
  selectedReportRun,
  selectedRunSummary,
}: DecisionProps) {
  const effectiveSummary = selectedRunSummary ?? projectSummary
  const effectiveReports = reports
  const critical = priorityCount(effectiveSummary, "critical")
  const high = priorityCount(effectiveSummary, "high")
  const kevHits = effectiveSummary?.kev_hits ?? 0
  const totalFindings = effectiveSummary?.finding_count ?? 0
  const openFindings = summaryOpenFindings(effectiveSummary)
  const executiveReport = reportForFormat(effectiveReports, "html")
  const bundle = evidenceBundleReport(effectiveReports)
  const problem =
    totalFindings > 0
      ? `${critical + high} critical/high findings across ${totalFindings} total; ${kevHits} known-exploited KEV entries.`
      : "No findings data available for this run."
  const businessImpact =
    critical > 0
      ? "Active exploitation risk across production or exposed services."
      : high > 0
        ? "Elevated remediation risk requiring owner follow-up."
        : "No urgent vulnerability cluster is visible in this run."
  const recommendation =
    critical + high > 0
      ? "Assign remediation owners, patch KEV-backed critical findings first, and validate fixed or VEX states."
      : "Maintain the standard remediation cadence and re-run after the next deployment cycle."
  const priority = critical > 0 ? "Immediate" : high > 0 ? "High" : "Routine"
  const priorityTone: VpwBadgeTone =
    critical > 0 ? "critical" : high > 0 ? "warning" : "success"
  const runId = selectedReportRun?.id.slice(0, 8) ?? "not selected"
  const decisionStatement = `${openFindings} open findings require remediation owner assignment. Evidence artifacts for run ${runId} are available for audit review.`
  const evidenceBasis = [
    `Run ${runId}`,
    `Provider snapshot ${providerSnapshotShortId(selectedReportRun, null)}`,
    "CVSS/EPSS/KEV",
    "Asset context when supplied",
    "VEX/accepted-risk where available",
  ].join(" · ")

  return (
    <VpwPanel className="flex flex-col gap-5 p-5">
      <VpwSectionHeader
        description="Risk translated to business language for review."
        eyebrow="Decision Summary"
        title="Executive Decision Summary"
      />
      <VpwGrid columns={2}>
        <DecisionBlock label="Problem" value={problem} />
        <DecisionBlock label="Business impact" value={businessImpact} />
        <DecisionBlock
          label="Recommended owner action"
          value={recommendation}
        />
        <DecisionBlock
          label="Priority / SLA"
          tone={priorityTone}
          value={
            critical > 0
              ? `${priority} / 48 hours for critical KEV-backed findings`
              : priority
          }
        />
      </VpwGrid>
      <VpwStatusBanner title="Decision statement" tone="info">
        {decisionStatement}
      </VpwStatusBanner>
      <VpwKeyValueList
        items={[
          {
            label: "Evidence basis",
            value: evidenceBasis,
          },
        ]}
      />
      <div className="flex flex-wrap gap-2">
        <Button asChild variant="outline">
          <Link
            search={selectedProjectRouteSearch(selectedProject?.id ?? "")}
            to="/findings"
          >
            Open Triage
          </Link>
        </Button>
        {executiveReport ? (
          <Button
            onClick={() => void onDownloadReport(executiveReport)}
            type="button"
            variant="outline"
          >
            Download Executive Report
          </Button>
        ) : (
          <Button
            disabled={!selectedReportRun}
            onClick={() => void onCreateReport("html")}
            type="button"
            variant="outline"
          >
            Generate executive HTML
          </Button>
        )}
        {bundle ? (
          <Button
            onClick={() => void onDownloadReport(bundle)}
            type="button"
            variant="outline"
          >
            Download Evidence ZIP
          </Button>
        ) : (
          <Button
            disabled={!selectedReportRun}
            onClick={() => void onCreateReport("zip")}
            type="button"
            variant="outline"
          >
            Build Evidence ZIP
          </Button>
        )}
      </div>
    </VpwPanel>
  )
}

function DecisionBlock({
  label,
  tone,
  value,
}: {
  label: string
  tone?: VpwBadgeTone
  value: string
}) {
  return (
    <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-4">
      <p className="vpw-label">{label}</p>
      <p
        className="mt-2 text-sm leading-6 text-[var(--vpw-text-secondary)]"
        data-tone={tone}
      >
        {value}
      </p>
    </div>
  )
}

export function QualityFacts({
  providerStatus,
  reports,
  selectedReportRun,
  selectedRunSummary,
  verificationLoading,
  verificationReport,
  verificationReportTarget,
}: {
  providerStatus: ProviderStatusPublic | null
  reports: ReportPublic[]
  selectedReportRun: AnalysisRunPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  verificationLoading: boolean
  verificationReport: ReportVerificationPublic | null
  verificationReportTarget: ReportPublic | null
}) {
  const effectiveReports = reports
  const bundle = evidenceBundleReport(effectiveReports)
  const parserIssueCount = selectedRunSummary?.parse_errors?.length ?? 0
  const ignoredLines = selectedRunSummary?.ignored_lines ?? 0
  const coverage = contextCoverageFacts(selectedRunSummary, selectedReportRun)
  const htmlReport = reportForFormat(effectiveReports, "html")
  const markdownReport = reportForFormat(effectiveReports, "markdown")
  const verificationLabel = artifactVerificationLabel({
    report: bundle,
    verificationLoading,
    verificationReport,
    verificationReportTarget,
  })

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <VpwPanel className="p-4">
        <VpwSectionHeader eyebrow="Provider" title="Provider snapshot" />
        <VpwKeyValueList
          density="compact"
          items={[
            {
              label: "Freshness",
              tone: providerStatus?.status === "ok" ? "success" : "warning",
              value: providerStatus?.status ?? "Unavailable",
              description:
                providerStatus?.snapshot.id ??
                selectedReportRun?.provider_snapshot_id ??
                "No snapshot ID recorded",
            },
          ]}
        />
      </VpwPanel>
      <VpwPanel className="p-4">
        <VpwSectionHeader eyebrow="Parser" title="Parser quality" />
        <VpwKeyValueList
          columns={2}
          density="compact"
          items={[
            {
              label: "Parser errors",
              tone: parserIssueCount > 0 ? "warning" : "success",
              value: parserIssueCount,
            },
            {
              label: "Ignored rows",
              tone: ignoredLines > 0 ? "warning" : "success",
              value: ignoredLines,
            },
          ]}
        />
      </VpwPanel>
      <VpwPanel className="p-4">
        <VpwSectionHeader eyebrow="Integrity" title="Artifact integrity" />
        <VpwKeyValueList
          density="compact"
          items={[
            {
              label: "Evidence ZIP",
              tone: bundle ? "success" : "warning",
              value: bundle ? "Bundle checksum recorded" : "Not built",
              description:
                bundle?.sha256 ??
                "Build the bundle to record checksum evidence.",
            },
            {
              label: "Verification",
              tone: verificationLabel === "Verified" ? "success" : "warning",
              value: verificationLabel,
            },
            {
              label: "Report completeness",
              tone:
                htmlReport && markdownReport && bundle ? "success" : "warning",
              value: `${htmlReport ? "HTML generated" : "HTML missing"} · ${markdownReport ? "Markdown generated" : "Markdown missing"} · ${bundle ? "ZIP built" : "ZIP missing"}`,
            },
          ]}
        />
      </VpwPanel>
      <VpwPanel className="p-4">
        <VpwSectionHeader eyebrow="Coverage" title="Context coverage" />
        <VpwKeyValueList
          density="compact"
          items={[
            { label: "Asset context", value: coverage.assetContext },
            { label: "VEX", value: coverage.vex },
            { label: "ATT&CK mapping", value: coverage.attack },
            { label: "Accepted risk", value: coverage.acceptedRisk },
          ]}
        />
      </VpwPanel>
      <VpwPanel className="p-4 lg:col-span-2">
        <VpwSectionHeader eyebrow="Limitations" title="Known limitations" />
        <p className="text-sm leading-6 text-[var(--vpw-text-secondary)]">
          Missing optional context is shown as optional missing, not as a failed
          evidence state. Failed parser output, unavailable mandatory run data,
          or failed report generation should be treated as blocking issues.
        </p>
      </VpwPanel>
    </div>
  )
}
