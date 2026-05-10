import type {
  AnalysisRunPublic,
  AnalysisRunSummaryPublic,
  ProjectDecisionSummaryPublic,
  ProviderStatusPublic,
  ReportPublic,
} from "@/api-client"
import {
  type VpwBadgeTone,
  VpwExecutiveDecisionSummary,
  VpwKeyValueList,
} from "@/components/vpw"
import { DEMO_REPORTS, DEMO_SUMMARY } from "@/lib/demo-data"
import { formatProviderFreshness } from "@/lib/provider-format"
import { priorityCount, summaryOpenFindings } from "./evidence-center-model"

type DecisionProps = {
  projectSummary: ProjectDecisionSummaryPublic | null
  selectedRunSummary: AnalysisRunSummaryPublic | null
  selectedReportRun: AnalysisRunPublic | null
  isDemo: boolean
}

export function ExecutiveDecision({
  isDemo,
  selectedReportRun,
  selectedRunSummary,
}: DecisionProps) {
  const effectiveSummary = isDemo ? DEMO_SUMMARY : selectedRunSummary
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

export function QualityFacts({
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
