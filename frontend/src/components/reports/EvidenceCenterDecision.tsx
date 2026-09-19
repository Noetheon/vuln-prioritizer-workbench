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
import {
  type ArtifactCard,
  artifactCardForFormat,
} from "@/lib/report-capability-catalog"
import { Link } from "@/lib/router"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  artifactVerificationLabel,
  contextCoverageFacts,
  evidenceBundleReport,
  providerSnapshotShortId,
  reportForFormat,
} from "./evidence-center-model"
import { executiveDecisionFacts } from "./executive-decision-model"

type DecisionProps = {
  projectSummary: ProjectDecisionSummaryPublic | null
  selectedProject: ProjectPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  selectedReportRun: AnalysisRunPublic | null
  reports: ReportPublic[]
  onCreateReport: (format: "html" | "zip") => Promise<void>
  onDownloadReport: (report: ReportPublic) => Promise<void>
  artifactCards: readonly ArtifactCard[]
}

export function ExecutiveDecision({
  onCreateReport,
  onDownloadReport,
  reports,
  selectedProject,
  selectedReportRun,
  selectedRunSummary,
  artifactCards,
}: DecisionProps) {
  const effectiveReports = reports
  const facts = executiveDecisionFacts(selectedRunSummary)
  const executiveReport = reportForFormat(effectiveReports, "html")
  const bundle = evidenceBundleReport(effectiveReports)
  const htmlCard = artifactCardForFormat(artifactCards, "html")
  const zipCard = artifactCardForFormat(artifactCards, "zip")
  const runId = selectedReportRun?.id.slice(0, 8) ?? "not selected"
  const providerSnapshotId = providerSnapshotShortId(selectedReportRun, null)

  return (
    <VpwPanel className="flex flex-col gap-5 p-5">
      <VpwSectionHeader
        description="Recorded decision guidance for the selected evaluation."
        eyebrow="Decision Summary"
        title="Executive Decision Summary"
      />
      <VpwGrid columns={2}>
        <DecisionBlock label="Recorded findings" value={facts.problem} />
        <DecisionBlock label="Recommendations" value={facts.recommendations} />
        <DecisionBlock label="Shortest actionable SLA" value={facts.sla} />
        <DecisionBlock label="Guidance coverage" value={facts.coverage} />
      </VpwGrid>
      {facts.decisions.map((decision) => (
        <div
          key={decision.finding_id}
          className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] p-4"
        >
          <Link
            to="/findings/$findingId"
            params={{ findingId: decision.finding_id }}
            search={selectedProjectRouteSearch(selectedProject?.id ?? "")}
            className="text-sm font-semibold underline underline-offset-4"
          >
            {decision.cve_id} · {decision.component ?? "Component not recorded"}{" "}
            · {decision.target ?? "Target not recorded"}
          </Link>
          <p className="mt-2 text-sm">{decision.guidance.decision_statement}</p>
          <p className="mt-2 text-sm text-[var(--vpw-text-secondary)]">
            {decision.guidance.business_impact.text}
          </p>
          <p className="mt-2 text-xs text-[var(--vpw-text-muted)]">
            {decision.guidance.recommendation_label} ·{" "}
            {decision.guidance.sla.label}
          </p>
        </div>
      ))}
      <VpwStatusBanner title="Evidence scope" tone="info">
        These statements describe the selected run at evaluation time. Current
        finding detail may contain later decisions. KEV catalog membership alone
        does not confirm an incident in this project.
      </VpwStatusBanner>
      <VpwKeyValueList
        items={[
          {
            label: "Evidence basis",
            value: (
              <>
                Run <span data-vpw-visual-mask="true">{runId}</span> · Provider
                snapshot{" "}
                <span data-vpw-visual-mask="true">{providerSnapshotId}</span> ·
                CVSS/EPSS/KEV · Asset context when supplied · VEX/accepted-risk
                where available
              </>
            ),
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
            disabled={!selectedReportRun || !htmlCard}
            onClick={() => void onCreateReport("html")}
            type="button"
            variant="outline"
          >
            {htmlCard?.actionLabel ?? "Generate executive HTML"}
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
            disabled={!selectedReportRun || !zipCard}
            onClick={() => void onCreateReport("zip")}
            type="button"
            variant="outline"
          >
            {zipCard?.actionLabel ?? "Build Evidence ZIP"}
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
  const providerSnapshotDescription =
    selectedReportRun?.provider_snapshot_id ?? "No snapshot ID recorded"
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
              label: "Selected run snapshot",
              value: providerSnapshotDescription,
            },
            {
              label: "Current provider inventory",
              tone: providerStatus?.status === "ok" ? "success" : "warning",
              value: providerStatus?.status ?? "Unavailable",
              description: (
                <span
                  data-vpw-visual-mask={
                    providerSnapshotDescription === "No snapshot ID recorded"
                      ? undefined
                      : "true"
                  }
                >
                  {providerStatus?.snapshot.id ??
                    "No current snapshot recorded"}
                </span>
              ),
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
              description: bundle?.sha256 ? (
                <span data-vpw-visual-mask="true">{bundle.sha256}</span>
              ) : (
                "Build the bundle to record checksum evidence."
              ),
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
