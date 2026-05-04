import { Link, useLocation, useNavigate } from "@tanstack/react-router"
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BarChart3,
  Database,
  Gauge,
  GitBranch,
  Globe,
  ShieldCheck,
} from "lucide-react"
import { type FormEvent, lazy, Suspense, useEffect, useState } from "react"
import {
  type AnalysisRunPublic,
  type AnalysisRunSummaryPublic,
  ApiError,
  type ApiTokenCreatePublic,
  type ApiTokenPublic,
  ApiTokensService,
  type FindingDetailPublic,
  type FindingExplanationPublic,
  type FindingOccurrencePublic,
  type FindingPriority,
  type FindingPublic,
  FindingsService,
  type ImportParseErrorPublic,
  ImportsService,
  OpenAPI,
  type ProjectAttackSummaryPublic,
  type ProjectAttackTechniqueSummaryPublic,
  type ProjectDecisionSummaryPublic,
  type ProjectGovernanceRollupsPublic,
  type ProjectPublic,
  ProjectsService,
  type ProviderSourceStatusPublic,
  type ProviderStatusPublic,
  ProvidersService,
  type ReportPublic,
  ReportsService,
  type ReportVerificationPublic,
  RunsService,
  type UserPublic,
  UsersService,
  type WaiverPublic,
  WaiversService,
  WorkbenchService,
  type WorkbenchStatus,
} from "../api-client"
import { clearAccessToken, getAccessToken } from "../auth"
import {
  ProductAppShell,
  type WorkbenchPath,
} from "../components/app/AppShell"
import {
  FindingsByPriorityChart,
  RiskTrendChart,
  TopServicesByRiskChart,
} from "../components/charts"
import {
  ProviderFreshnessPanel,
  TopRemediationQueue,
} from "../components/dashboard"
import {
  CvssBadge,
  EpssBadge,
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
  RiskScore,
} from "../components/risk"
import {
  type DataQualityNoticeItem,
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from "../components/states"
import { Badge } from "../components/ui/badge"
import { Button } from "../components/ui/button"
import { Skeleton } from "../components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs"
import {
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "../components/vpw"
import {
  type ApiTokenScope,
  apiTokenScopeOptions,
  canonicalApiTokenScopes,
  defaultApiTokenScopes,
  defaultFindingFilters,
  defaultImportWizardState,
  emptyProjectForm,
  type FindingDetailTab,
  type FindingFilters,
  type FindingsDirection,
  type FindingsSort,
  findingPageSizes,
  type ImportFormat,
  type ImportUploadFormData,
  type ImportWizardState,
  mvpImportFormats,
  type ProjectFormState,
  type TemplateReportFormat,
  evidenceTimeline as timeline,
} from "../lib/app-defaults"
import {
  analysisRunIdFromError,
  apiErrorDetail,
  apiErrorMessage,
  arrayRecords,
  joinedValues,
  objectRecord,
  parseErrorsFromError,
  stringValue,
} from "../lib/app-errors"
import { routeDetails } from "../lib/app-route-config"
import {
  type EpssBucketCounts,
  epssBucketChartData,
  findingsByPriorityChartData,
  runActivityTrendData,
  topServicesByRiskChartData,
} from "../lib/chart-data"
import {
  DEMO_FINDING_ATTACK_CONTEXTS,
  DEMO_FINDINGS,
  DEMO_PROJECT,
} from "../lib/demo-data"
import {
  formatCacheAge,
  formatProviderFreshness,
  providerDataQualityNotes,
  providerSnapshotSummary,
} from "../lib/provider-format"
import {
  formatEpss,
  formatKev,
  formatNullableNumber,
  runStatusLabel,
} from "../lib/risk-format"
import { formatLabel as labelize, optionalText } from "../lib/ui-copy"
import { cn } from "../lib/utils"
import {
  type FindingWaiverEvidence,
  findingWaiverEvidence,
  validateWaiverForm,
  type WaiverFormState,
  waiverFormDefaults,
  waiverRequestBody,
  waiverScopeLabel,
} from "../lib/waiver-view"

const RiskOperationsDashboard = lazy(() =>
  import("../components/dashboard/RiskOperationsDashboard").then((module) => ({
    default: module.RiskOperationsDashboard,
  })),
)
const RemediationQueue = lazy(() =>
  import("../components/findings/RemediationQueue").then((module) => ({
    default: module.RemediationQueue,
  })),
)
const ImportsWorkbench = lazy(() =>
  import("../components/imports/ImportsWorkbench").then((module) => ({
    default: module.ImportsWorkbench,
  })),
)
const ProjectsWorkbench = lazy(() =>
  import("../components/projects/ProjectsWorkbench").then((module) => ({
    default: module.ProjectsWorkbench,
  })),
)
const ProvidersRouteContainer = lazy(() =>
  import("../components/providers/ProvidersRouteContainer").then((module) => ({
    default: module.ProvidersRouteContainer,
  })),
)
const EvidenceCenter = lazy(() =>
  import("../components/reports/EvidenceCenter").then((module) => ({
    default: module.EvidenceCenter,
  })),
)
const SettingsRouteContainer = lazy(() =>
  import("../components/settings/SettingsRouteContainer").then((module) => ({
    default: module.SettingsRouteContainer,
  })),
)
const WaiversWorkbench = lazy(() =>
  import("../components/waivers/WaiversWorkbench").then((module) => ({
    default: module.WaiversWorkbench,
  })),
)

type FindingAttackContext = NonNullable<FindingDetailPublic["attack_context"]>

type FindingDecisionReason = {
  detail: string
  label: string
  tone: "critical" | "warning" | "info" | "positive"
}

type FindingDetailRow = {
  detail?: string
  label: string
  value: string
}

function _priorityCount(
  summary: ProjectDecisionSummaryPublic | null,
  priority: "Critical" | "High" | "Medium" | "Low",
) {
  return summary?.counts_by_priority?.[priority] ?? 0
}

type DashboardSignalCounts = {
  highEpss: number
  internetFacingCriticals: number
  epssBuckets: EpssBucketCounts
}

function buildDashboardCards(
  summary: ProjectDecisionSummaryPublic | null,
  providerStatus: ProviderStatusPublic | null,
  loading: boolean,
  signalCountsLoading: boolean,
  signalCounts: DashboardSignalCounts,
) {
  const providerFreshness = formatProviderFreshness(providerStatus)
  return [
    {
      label: "Critical Open",
      value: loading ? "Loading" : String(summary?.open_finding_count ?? 0),
      detail: "open, in review, or remediating",
      icon: AlertTriangle,
      tone: "critical",
    },
    {
      label: "KEV Exposed",
      value: loading ? "Loading" : String(summary?.kev_hits ?? 0),
      detail: "CISA KEV matches",
      icon: ShieldCheck,
      tone: "kev",
    },
    {
      label: "High EPSS",
      value:
        loading || signalCountsLoading
          ? "Loading"
          : String(signalCounts.highEpss),
      detail: "high-confidence EPSS findings (≥70%)",
      icon: Gauge,
      tone: "high",
    },
    {
      label: "Internet-facing Criticals",
      value:
        loading || signalCountsLoading
          ? "Loading"
          : String(signalCounts.internetFacingCriticals),
      detail: "critical findings with internet-facing exposure",
      icon: Globe,
      tone: "kev",
    },
    {
      label: "Provider Freshness",
      value: providerFreshness.value,
      detail: providerFreshness.detail,
      icon: Database,
      tone: providerFreshness.tone,
    },
    {
      label: "Latest Analysis",
      value: latestAnalysisValue(summary),
      detail: latestRunDetail(summary),
      icon: Activity,
      tone: "run",
    },
  ]
}

function buildSummaryRows(summary: ProjectDecisionSummaryPublic | null) {
  return [
    {
      label: "Open findings",
      value: String(summary?.open_finding_count ?? 0),
      detail: "open, in review, or remediating",
    },
    {
      label: "Total findings",
      value: String(summary?.finding_count ?? 0),
      detail: "persisted findings in project",
    },
    {
      label: "EPSS hits",
      value: String(summary?.epss_hits ?? 0),
      detail: "findings with EPSS context",
    },
    {
      label: "Known CVSS",
      value: String(summary?.cvss_known_count ?? 0),
      detail: "findings with CVSS base score",
    },
  ]
}

function attackSummaryRows(summary: ProjectAttackSummaryPublic | null) {
  return [
    {
      label: "Mapped",
      value: String(summary?.mapped_finding_count ?? 0),
      detail: `${summary?.mapped_coverage_percent ?? 0}% coverage`,
    },
    {
      label: "Unmapped",
      value: String(summary?.unmapped_finding_count ?? 0),
      detail: "findings without reviewed context",
    },
    {
      label: "Low confidence",
      value: String(summary?.confidence_distribution?.low ?? 0),
      detail: "visible review signal",
    },
  ]
}

function attackConfidenceSummary(summary: ProjectAttackSummaryPublic | null) {
  const counts = summary?.confidence_distribution ?? {}
  return ["high", "medium", "low", "unknown"]
    .map((key) => `${labelize(key)} ${counts[key] ?? 0}`)
    .join(" / ")
}

function attackTechniqueConfidenceLabel(
  technique: ProjectAttackTechniqueSummaryPublic,
) {
  const counts = technique.confidence_counts ?? {}
  const visible = ["high", "medium", "low", "unknown"]
    .map((key) => [key, counts[key] ?? 0] as const)
    .filter(([, count]) => count > 0)
  return visible.length > 0
    ? visible.map(([key, count]) => `${labelize(key)} ${count}`).join(" / ")
    : "Confidence unknown"
}

function governanceServiceRows(rollups: ProjectGovernanceRollupsPublic | null) {
  const services = rollups?.top_services_by_risk ?? []
  if (services.length > 0) {
    return { rows: services, source: "services" as const }
  }
  return { rows: rollups?.top_assets_by_risk ?? [], source: "assets" as const }
}

function waiverDebtRows(rollups: ProjectGovernanceRollupsPublic | null) {
  return rollups?.waiver_debt?.items ?? []
}

function waiverDebtSummaryRows(rollups: ProjectGovernanceRollupsPublic | null) {
  const debt = rollups?.waiver_debt
  return [
    {
      label: "Expired",
      value: String(debt?.expired_count ?? 0),
      detail: "past expiry",
    },
    {
      label: "Review due",
      value: String(debt?.review_due_count ?? 0),
      detail: "needs owner review",
    },
    {
      label: "Expiring soon",
      value: String(debt?.expiring_soon_count ?? 0),
      detail: "within 14 days",
    },
    {
      label: "Accepted findings",
      value: String(debt?.accepted_finding_count ?? 0),
      detail: "currently accepted",
    },
  ]
}

function serviceWaiverDebtCount(
  service: NonNullable<
    ProjectGovernanceRollupsPublic["top_services_by_risk"]
  >[number],
) {
  return (
    (service.expired_waiver_count ?? 0) + (service.review_due_waiver_count ?? 0)
  )
}

function formatRollupScore(value: number | null | undefined) {
  if (value === null || value === undefined) {
    return "0"
  }
  return Number.isInteger(value) ? String(value) : value.toFixed(1)
}

function _formatRunStatus(
  status: ProjectDecisionSummaryPublic["latest_run_status"],
) {
  return status ? status.replaceAll("_", " ") : "No runs"
}

function latestRunDetail(summary: ProjectDecisionSummaryPublic | null) {
  if (!summary?.latest_run_id) {
    return "import required"
  }
  return `run ${summary.latest_run_id.slice(0, 8)}`
}

function latestAnalysisValue(summary: ProjectDecisionSummaryPublic | null) {
  if (!summary?.latest_run_id) {
    return "No run yet"
  }
  return latestRunStatusLabel(summary)
}

function latestRunStatusLabel(
  summary: ProjectDecisionSummaryPublic | null,
): string {
  if (!summary?.latest_run_status) {
    return "Complete"
  }
  return runStatusLabel(summary.latest_run_status)
}

function _importAccept(inputType: ImportFormat) {
  return mvpImportFormats.find((format) => format.value === inputType)?.accept
}

function _runFileLabel(run: {
  filename?: string | null
  input_type: string
  input_upload?: Record<string, unknown>
  summary_json?: Record<string, unknown>
}) {
  const upload = objectRecord(
    run.input_upload ?? run.summary_json?.input_upload,
  )
  const uploadFilename = stringValue(upload.filename)
  return run.filename ?? uploadFilename ?? `${run.input_type} upload`
}

function _failedRunCause(
  run: AnalysisRunPublic | null,
  summary: AnalysisRunSummaryPublic | null,
) {
  if (!run && !summary) {
    return "No failure detail available."
  }
  const errorJson = objectRecord(summary?.error_json ?? run?.error_json)
  const analysisError = objectRecord(errorJson.analysis_error)
  return (
    run?.error_message ??
    stringValue(errorJson.message) ??
    stringValue(errorJson.error) ??
    stringValue(errorJson.last_error) ??
    stringValue(analysisError.message) ??
    "No failure detail available."
  )
}

const decisionReasonCopy: Record<string, { label: string; detail: string }> = {
  "asset.context": {
    detail: "Asset context influences operational priority.",
    label: "Asset context",
  },
  "asset.context_unknown": {
    detail:
      "Asset context is missing and must be validated before final scheduling.",
    label: "Asset context unknown",
  },
  "operational.score": {
    detail: "Combined signals determine the operational remediation score.",
    label: "Operational score",
  },
  "priority.critical.epss_cvss": {
    detail: "EPSS and CVSS together indicate critical remediation urgency.",
    label: "Critical EPSS and CVSS",
  },
  "priority.high.cvss": {
    detail: "CVSS indicates high impact severity.",
    label: "High CVSS",
  },
  "priority.high.epss": {
    detail: "EPSS indicates elevated exploitation probability.",
    label: "High EPSS",
  },
  "priority.kev.known_exploited": {
    detail: "Known exploited vulnerability signal is present.",
    label: "Known exploited vulnerability",
  },
  "priority.medium.cvss": {
    detail: "CVSS contributes meaningful impact severity.",
    label: "Medium CVSS signal",
  },
  "priority.medium.epss": {
    detail: "EPSS contributes exploitation probability context.",
    label: "Medium EPSS signal",
  },
}

function humanizeDecisionReasonText(value: string | null | undefined) {
  if (!value) {
    return value
  }
  return Object.entries(decisionReasonCopy).reduce(
    (text, [code, copy]) =>
      text.replaceAll(code, copy.detail.replace(/\.$/, "")),
    value,
  )
}

function decisionReasonLabel(value: string | null | undefined) {
  if (!value) {
    return "Reason"
  }
  return decisionReasonCopy[value]?.label ?? labelize(value)
}

function decisionReasonDetail(
  code: string | null | undefined,
  detail: string | null | undefined,
) {
  return (
    humanizeDecisionReasonText(detail) ?? decisionReasonCopy[code ?? ""]?.detail
  )
}

function _findingOverviewCards(finding: FindingDetailPublic) {
  return [
    {
      detail:
        finding.epss === null || finding.epss === undefined
          ? "EPSS provider data missing"
          : "FIRST EPSS probability",
      label: "EPSS",
      value: formatEpss(finding.epss),
    },
    {
      detail:
        finding.cvss_base_score === null ||
        finding.cvss_base_score === undefined
          ? "CVSS provider data missing"
          : "NVD base score",
      label: "CVSS",
      value: formatNullableNumber(finding.cvss_base_score),
    },
    {
      detail: finding.in_kev ? "CISA KEV matched" : "No KEV match recorded",
      label: "KEV",
      value: formatKev(finding.in_kev),
    },
    {
      detail: joinedValues([
        finding.owner,
        finding.business_service,
        labelize(finding.asset_environment),
        labelize(finding.asset_criticality),
        labelize(finding.exposure),
        finding.asset_target_ref,
      ]),
      label: "Asset",
      value: findingAssetLabel(finding),
    },
  ]
}

function findingOccurrenceRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
): Array<Partial<FindingOccurrencePublic> & Record<string, unknown>> {
  if (finding?.occurrences?.length) {
    return finding.occurrences
  }
  const explanationPayload = objectRecord(explanation?.explanation)
  const explanationProvenance = objectRecord(explanationPayload.provenance)
  const findingProvenance = objectRecord(
    objectRecord(finding?.explanation_json).provenance,
  )
  return arrayRecords(
    explanationProvenance.occurrences ?? findingProvenance.occurrences,
  ).map((occurrence, index) => ({
    ...occurrence,
    id: stringValue(occurrence.id) ?? `occurrence-${index + 1}`,
  }))
}

function findingWhyText(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const decisionExplanation = objectRecord(explanation?.decision_explanation)
  const fallback = "No priority explanation has been recorded for this finding."
  return (
    humanizeDecisionReasonText(
      stringValue(decisionExplanation.human_readable) ??
        stringValue(decisionExplanation.summary) ??
        explanation?.rationale ??
        finding?.rationale ??
        fallback,
    ) ?? fallback
  )
}

function findingRecommendedAction(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const decisionGuidance = objectRecord(explanation?.decision_guidance)
  return (
    stringValue(decisionGuidance.recommended_action) ??
    explanation?.recommended_action ??
    finding?.recommended_action ??
    "No recommended action has been recorded."
  )
}

function findingComponentDetailLabel(finding: FindingDetailPublic | null) {
  if (!finding) {
    return "N.A."
  }
  const name = optionalText(finding.component_name)
  return finding.component_version
    ? `${name} ${finding.component_version}`
    : name
}

function findingAssetServiceDetailLabel(finding: FindingDetailPublic | null) {
  if (!finding) {
    return "N.A."
  }
  return joinedValues([
    finding.business_service,
    finding.asset_name,
    finding.asset_key,
    finding.asset_target_ref,
  ])
}

function findingOwnerDetailLabel(
  finding: FindingDetailPublic | null,
  occurrences: Array<
    Partial<FindingOccurrencePublic> & Record<string, unknown>
  >,
) {
  return (
    finding?.owner ?? stringValue(occurrences[0]?.asset_owner) ?? "Unassigned"
  )
}

function findingSlaLabel(priority: FindingPriority | undefined) {
  switch (priority) {
    case "critical":
      return "24 hours"
    case "high":
      return "7 days"
    case "medium":
      return "30 days"
    case "low":
      return "90 days"
    default:
      return "Define during triage"
  }
}

function findingNextStepLabel(finding: FindingDetailPublic | null) {
  switch (finding?.status) {
    case "open":
      return "Assign remediation work and start fix validation."
    case "in_review":
      return "Complete technical review and confirm the remediation path."
    case "remediating":
      return "Verify the fix, then update evidence and status."
    case "fixed":
      return "Confirm scanner closure and keep evidence for reporting."
    case "accepted":
      return "Track accepted risk until the next review date."
    case "suppressed":
      return "Verify the VEX or suppression scope still applies."
    default:
      return "Confirm ownership and record the next remediation step."
  }
}

function isInternetFacingExposure(value: string | null | undefined) {
  return value ? value.toLowerCase().includes("internet") : false
}

function isProductionEnvironment(value: string | null | undefined) {
  return value ? /\bprod(uction)?\b/i.test(value.replaceAll("_", " ")) : false
}

function findingDecisionReasonRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
  attackContext: FindingAttackContext | null,
) {
  const rows: FindingDecisionReason[] = []

  if (finding?.in_kev) {
    rows.push({
      detail:
        "CISA KEV is recorded for this CVE, so exploitation is a confirmed prioritization signal.",
      label: "CISA KEV listed",
      tone: "critical",
    })
  }

  if (finding?.epss !== null && finding?.epss !== undefined) {
    rows.push({
      detail:
        finding.epss >= 0.7
          ? `${formatEpss(finding.epss)} EPSS indicates elevated exploitation probability.`
          : `${formatEpss(finding.epss)} EPSS is recorded for the decision model.`,
      label: finding.epss >= 0.7 ? "High EPSS" : "EPSS recorded",
      tone: finding.epss >= 0.7 ? "warning" : "info",
    })
  }

  if (
    finding?.cvss_base_score !== null &&
    finding?.cvss_base_score !== undefined
  ) {
    rows.push({
      detail:
        finding.cvss_base_score >= 9
          ? `CVSS ${formatNullableNumber(finding.cvss_base_score)} is critical impact severity.`
          : `CVSS ${formatNullableNumber(finding.cvss_base_score)} contributes to the risk score.`,
      label: finding.cvss_base_score >= 9 ? "Critical CVSS" : "CVSS recorded",
      tone: finding.cvss_base_score >= 9 ? "critical" : "info",
    })
  }

  if (isInternetFacingExposure(finding?.exposure)) {
    rows.push({
      detail: `${finding ? findingAssetLabel(finding) : "Asset"} is marked ${labelize(finding?.exposure)}, increasing remediation urgency.`,
      label: "Internet-facing asset",
      tone: "critical",
    })
  }

  if (isProductionEnvironment(finding?.asset_environment)) {
    rows.push({
      detail: `Environment is marked ${labelize(finding?.asset_environment)}, so operational exposure is higher.`,
      label: "Production service",
      tone: "warning",
    })
  }

  if (!attackContextEmptyState(attackContext)) {
    rows.push({
      detail: `${attackTechniqueRows(attackContext).length} reviewed ATT&CK technique mapping(s) are available for defensive context.`,
      label: "ATT&CK / TTP context",
      tone: "warning",
    })
  }

  const defensiveNote = stringValue(attackContext?.defensive_note)
  if (defensiveNote && /gap|missing|coverage|detect/i.test(defensiveNote)) {
    rows.push({
      detail: defensiveNote,
      label: "Detection coverage gap",
      tone: "warning",
    })
  }

  const recommendedAction = findingRecommendedAction(finding, explanation)
  if (recommendedAction !== "No recommended action has been recorded.") {
    rows.push({
      detail: recommendedAction,
      label: "Fix or mitigation",
      tone: "positive",
    })
  }

  if (rows.length === 0) {
    rows.push({
      detail: findingWhyText(finding, explanation),
      label: "Decision rationale",
      tone: "info",
    })
  }

  return rows
}

function findingReasonRows(explanation: FindingExplanationPublic | null) {
  const decisionExplanation = objectRecord(explanation?.decision_explanation)
  const reasons = arrayRecords(decisionExplanation.reasons)
  return reasons.map((reason, index) => {
    const code =
      stringValue(reason.code) ??
      stringValue(reason.signal) ??
      stringValue(reason.source)
    const detail =
      decisionReasonDetail(
        code,
        stringValue(reason.message) ??
          stringValue(reason.description) ??
          stringValue(reason.detail) ??
          stringValue(reason.value) ??
          null,
      ) ?? "Matched decision signal"
    return {
      detail,
      label: code ? decisionReasonLabel(code) : `Reason ${index + 1}`,
    }
  })
}

function findingDataQualityRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  const flags =
    explanation?.data_quality_flags ??
    arrayRecords(objectRecord(finding?.data_quality_json).flags)
  return flags.map((flag, index) => ({
    code: stringValue(flag.code) ?? "data_quality_flag",
    key: [flag.source, flag.code, flag.message, index].join(":"),
    message: stringValue(flag.message) ?? "Data quality flag recorded.",
    severity: stringValue(flag.severity) ?? "info",
    source: stringValue(flag.source) ?? "provider",
  }))
}

function findingProviderGaps(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
) {
  if (!finding) {
    return []
  }
  const providerEvidence = objectRecord(
    explanation?.provider_evidence ??
      objectRecord(finding.explanation_json).provider_evidence,
  )
  const gaps: string[] = []
  if (finding.epss === null || finding.epss === undefined) {
    gaps.push("EPSS missing")
  }
  if (
    finding.cvss_base_score === null ||
    finding.cvss_base_score === undefined
  ) {
    gaps.push("CVSS missing")
  }
  if (Object.keys(providerEvidence).length === 0) {
    gaps.push("Provider evidence missing")
  }
  return gaps
}

function findingEvidenceRows(
  finding: FindingDetailPublic | null,
  explanation: FindingExplanationPublic | null,
  occurrences: Array<
    Partial<FindingOccurrencePublic> & Record<string, unknown>
  >,
  dataQualityRows: ReturnType<typeof findingDataQualityRows>,
  providerGaps: string[],
): FindingDetailRow[] {
  const firstOccurrence = occurrences[0]
  const providerEvidence = objectRecord(
    explanation?.provider_evidence ??
      objectRecord(finding?.explanation_json).provider_evidence,
  )
  const evidence = objectRecord(finding?.evidence_json)
  const providerSignalLabels = [
    finding?.epss !== null && finding?.epss !== undefined ? "EPSS" : null,
    finding?.cvss_base_score !== null && finding?.cvss_base_score !== undefined
      ? "CVSS"
      : null,
    finding?.in_kev ? "CISA KEV" : null,
  ].filter((label): label is string => Boolean(label))
  const providerKeys = Object.keys(providerEvidence)
  const artifactRef =
    stringValue(evidence.report_artifact) ??
    stringValue(evidence.report_reference) ??
    stringValue(evidence.artifact_reference) ??
    stringValue(firstOccurrence?.vex_source_path)

  return [
    {
      detail:
        providerGaps.length > 0
          ? `Gaps: ${providerGaps.join(", ")}`
          : "No provider gaps recorded for the stored finding signals.",
      label: "Provider snapshot",
      value:
        providerKeys.length > 0
          ? `${providerKeys.length} provider evidence field(s) recorded`
          : providerSignalLabels.length > 0
            ? providerSignalLabels.join(", ")
            : "No provider snapshot recorded",
    },
    {
      detail: optionalText(
        stringValue(firstOccurrence?.source_record_id) ??
          stringValue(firstOccurrence?.raw_reference) ??
          stringValue(firstOccurrence?.source_id),
      ),
      label: "Input source",
      value: optionalText(
        stringValue(firstOccurrence?.source_format) ??
          stringValue(firstOccurrence?.source) ??
          stringValue(evidence.input_source),
      ),
    },
    {
      detail: optionalText(stringValue(firstOccurrence?.raw_severity)),
      label: "Scanner evidence",
      value: optionalText(
        stringValue(firstOccurrence?.scanner) ??
          stringValue(evidence.scanner) ??
          stringValue(evidence.tool),
      ),
    },
    {
      detail:
        dataQualityRows.length > 0
          ? dataQualityRows.map((row) => labelize(row.code)).join(", ")
          : "No data quality flags recorded.",
      label: "Data quality notes",
      value:
        explanation?.data_quality_confidence ??
        stringValue(objectRecord(finding?.data_quality_json).confidence) ??
        "Recorded",
    },
    {
      detail:
        "Report or evidence bundle reference when supplied by input data.",
      label: "Report / artifact references",
      value: optionalText(artifactRef),
    },
  ]
}

function findingHistoryRows(
  finding: FindingDetailPublic | null,
  occurrences: Array<
    Partial<FindingOccurrencePublic> & Record<string, unknown>
  >,
  waiverEvidence: FindingWaiverEvidence | null,
): FindingDetailRow[] {
  const vexStatus =
    occurrences
      .map((occurrence) => stringValue(occurrence.vex_status))
      .find(Boolean) ?? null
  const vexDetail =
    occurrences
      .map((occurrence) =>
        joinedValues([
          stringValue(occurrence.vex_justification),
          stringValue(occurrence.vex_action_statement),
          stringValue(occurrence.vex_match_type),
        ]),
      )
      .find((value) => value !== "N.A.") ?? null

  return [
    {
      detail: "Initial source occurrence recorded by Workbench.",
      label: "First seen",
      value: finding?.first_seen_at
        ? formatDateTime(finding.first_seen_at)
        : "N.A.",
    },
    {
      detail: "Most recent source occurrence recorded by Workbench.",
      label: "Last seen",
      value: finding?.last_seen_at
        ? formatDateTime(finding.last_seen_at)
        : "N.A.",
    },
    {
      detail: finding?.updated_at
        ? `Last updated ${formatDateTime(finding.updated_at)}`
        : "No status update timestamp recorded.",
      label: "Status changes",
      value: labelize(finding?.status),
    },
    {
      detail:
        waiverEvidence?.reason ??
        vexDetail ??
        "No waiver or VEX state recorded for this finding.",
      label: "Waiver / VEX state",
      value: finding?.waived
        ? `Waived${waiverEvidence?.status ? ` (${labelize(waiverEvidence.status)})` : ""}`
        : finding?.suppressed_by_vex
          ? "Suppressed by VEX"
          : vexStatus
            ? labelize(vexStatus)
            : "Not accepted",
    },
  ]
}

function demoFindingDetailForId(findingId: string) {
  const demoFinding = DEMO_FINDINGS.find((finding) => finding.id === findingId)
  if (!demoFinding) {
    return null
  }
  const createdAt = demoFinding.created_at ?? "2025-04-01T00:00:00Z"
  const lastSeenAt = demoFinding.last_seen_at ?? createdAt
  return {
    ...demoFinding,
    asset_id: demoFinding.asset_id ?? null,
    component_id: demoFinding.component_id ?? null,
    created_at: createdAt,
    data_quality_json: {
      confidence: "Demo Preview",
      flags: [
        {
          code: "demo_preview",
          message:
            "Sample finding detail used only when no real project data is available.",
          severity: "info",
          source: "demo",
        },
      ],
    },
    evidence_json: {
      input_source: "Demo Preview sample queue",
      scanner: "Demo import",
    },
    first_seen_at: demoFinding.first_seen_at ?? createdAt,
    last_seen_at: lastSeenAt,
    attack_context: DEMO_FINDING_ATTACK_CONTEXTS[demoFinding.id] ?? null,
    occurrences: [
      {
        analysis_run_id: "demo-run-0001",
        asset_business_service: demoFinding.business_service,
        asset_exposure: demoFinding.exposure,
        asset_owner: demoFinding.owner,
        asset_ref:
          demoFinding.asset_name ??
          demoFinding.asset_key ??
          demoFinding.business_service,
        component_name: demoFinding.component_name,
        component_version: demoFinding.component_version,
        created_at: createdAt,
        fix_version: stringValue(demoFinding.recommended_action),
        id: `${demoFinding.id}-occurrence-1`,
        purl: demoFinding.component_purl,
        raw_severity: labelize(demoFinding.priority),
        scanner: "Demo import",
        source: "Demo Preview",
        source_format: "Sample finding",
        source_record_id: demoFinding.cve_id,
        target_kind: "service",
        target_ref: demoFinding.business_service,
      },
    ],
    project_id: DEMO_PROJECT.id,
    updated_at: demoFinding.updated_at ?? lastSeenAt,
    vulnerability_id: demoFinding.vulnerability_id ?? demoFinding.cve_id,
  } as FindingDetailPublic
}

function demoFindingExplanationForDetail(
  finding: FindingDetailPublic,
): FindingExplanationPublic {
  return {
    cve_id: finding.cve_id,
    data_quality_confidence: "Demo Preview",
    decision_explanation: {
      human_readable: findingWhyText(finding, null),
    },
    decision_guidance: {
      recommended_action: findingRecommendedAction(finding, null),
    },
    finding_id: finding.id,
    priority: finding.priority ?? "medium",
    priority_rank: finding.priority_rank ?? 0,
    project_id: finding.project_id,
    provider_evidence: {
      demo_preview: true,
      epss: finding.epss,
      cvss_base_score: finding.cvss_base_score,
      in_kev: finding.in_kev,
    },
    rationale: finding.rationale,
    recommended_action: finding.recommended_action,
    risk_score: finding.risk_score,
  }
}

function attackTechniqueRows(context: FindingAttackContext | null) {
  if (!context) {
    return []
  }
  const techniques = context.techniques ?? []
  if (techniques.length > 0) {
    return techniques
  }
  return (context.mappings ?? []).map((mapping) => ({
    confidence: mapping.confidence,
    defensive_note: mapping.defensive_note,
    name: mapping.technique_name,
    rationale: mapping.rationale,
    review_status: mapping.review_status,
    source: mapping.source,
    tactics: mapping.tactics ?? [],
    technique_id: mapping.technique_id,
    url: null,
  }))
}

function attackTacticsLabel(values: string[] | null | undefined) {
  return values && values.length > 0 ? values.join(", ") : "N.A."
}

function attackConfidenceLabel(value: string | null | undefined) {
  return value ? labelize(value) : "Unknown"
}

function attackSourceLabel(
  source: string | null | undefined,
  context: FindingAttackContext | null,
) {
  const references = (context?.mappings ?? []).flatMap(
    (mapping) => mapping.references ?? [],
  )
  if (
    references.some((reference) =>
      reference.toLowerCase().includes("local curated demo mapping"),
    )
  ) {
    return "Local curated demo mapping"
  }
  if (source === "local-curated") {
    return "Local curated mapping"
  }
  return source ?? null
}

function attackCoverageStatusLabel(context: FindingAttackContext | null) {
  const note = (stringValue(context?.defensive_note) ?? "").toLowerCase()
  if (!note) {
    return "Not recorded"
  }
  if (/partial|unknown/.test(note)) {
    return "Partial / unknown"
  }
  if (/gap|missing|validate|coverage|detect/.test(note)) {
    return "Needs validation"
  }
  return "Recorded"
}

function defensiveActionItems(value: string | null | undefined) {
  return (value ?? "")
    .split(/\n+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function attackContextEmptyState(context: FindingAttackContext | null) {
  return (
    !context ||
    context.mapped !== true ||
    attackTechniqueRows(context).length === 0
  )
}

function numericFilterValue(value: string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return undefined
  }
  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : undefined
}

function hasActiveFindingFilters(filters: FindingFilters) {
  return Object.values(filters).some((value) => value.trim() !== "")
}

function _findingComponentLabel(finding: FindingPublic) {
  const name = optionalText(finding.component_name)
  return finding.component_version
    ? `${name} ${finding.component_version}`
    : name
}

function findingAssetLabel(finding: FindingPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "N.A."
  )
}

function _metadataRows(value: unknown) {
  return Object.entries(objectRecord(value)).filter(
    ([key, entryValue]) =>
      !key.toLowerCase().includes("path") &&
      entryValue !== null &&
      entryValue !== undefined &&
      typeof entryValue !== "object",
  )
}

function _scalarRows(value: unknown) {
  return Object.entries(objectRecord(value)).filter(
    ([, entryValue]) =>
      entryValue !== null &&
      entryValue !== undefined &&
      typeof entryValue !== "object",
  )
}

function _jsonPreview(value: unknown) {
  const record = objectRecord(value)
  return Object.keys(record).length > 0
    ? JSON.stringify(record, null, 2)
    : "No error JSON recorded."
}

function _shortText(value: string | null | undefined, max = 16) {
  return value && value.length > max ? `${value.slice(0, max)}…` : (value ?? "")
}

function _displayValue(value: unknown, fallback = "N.A.") {
  if (value === null || value === undefined) {
    return fallback
  }
  if (typeof value === "string") {
    return value.trim() ? value : fallback
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value)
  }
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(", ") : fallback
  }
  if (typeof value === "object") {
    return JSON.stringify(value)
  }
  return String(value)
}

async function _copyValue(value: string) {
  if (!value || !window.navigator?.clipboard?.writeText) {
    return
  }
  try {
    await window.navigator.clipboard.writeText(value)
  } catch {
    return
  }
}

function _formatManifestFieldName(field: string) {
  return labelize(field.replace(/_/g, " "))
}

function _verificationItems(verification: ReportVerificationPublic | null) {
  return Array.isArray(verification?.items) ? verification.items : []
}

function _verificationSummaryRows(
  verification: ReportVerificationPublic | null,
) {
  return Object.entries(objectRecord(verification?.summary))
}

function validateProjectForm(form: ProjectFormState) {
  const name = form.name.trim()
  const description = form.description.trim()
  if (!name) {
    return "Project name is required."
  }
  if (name.length > 255) {
    return "Project name must be 255 characters or fewer."
  }
  if (description.length > 4096) {
    return "Project description must be 4096 characters or fewer."
  }
  return ""
}

function projectRequestBody(form: ProjectFormState) {
  const description = form.description.trim()
  return {
    description: description ? description : null,
    name: form.name.trim(),
  }
}

function formatDateTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "N.A."
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

function reportFormatLabel(format: string) {
  if (format === "zip") {
    return "Evidence ZIP"
  }
  if (format === "attack-navigator") {
    return "ATT&CK Navigator"
  }
  if (format === "sarif") {
    return "SARIF"
  }
  return format.toUpperCase()
}

function _reportSizeLabel(sizeBytes: number) {
  if (sizeBytes < 1024) {
    return `${sizeBytes} B`
  }
  if (sizeBytes < 1024 * 1024) {
    return `${(sizeBytes / 1024).toFixed(1)} KB`
  }
  return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`
}

function isReportableRun(run: AnalysisRunPublic | null) {
  return (
    run?.status === "succeeded" ||
    run?.status === "completed" ||
    run?.status === "completed_with_errors"
  )
}

function reportDownloadUrl(report: ReportPublic) {
  if (report.download_url.startsWith("http")) {
    return report.download_url
  }
  const base = OpenAPI.BASE.replace(/\/+$/, "")
  return `${base}${report.download_url}`
}

async function downloadReportArtifact(report: ReportPublic) {
  const token = getAccessToken()
  const response = await fetch(reportDownloadUrl(report), {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  })
  if (!response.ok) {
    let detail = ""
    try {
      detail = apiErrorDetail(await response.json()) ?? ""
    } catch {
      detail = ""
    }
    throw new Error(detail || `HTTP ${response.status}`)
  }
  const blob = await response.blob()
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = objectUrl
  anchor.download = report.filename
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(objectUrl)
}

function _providerSnapshotId(providerStatus: ProviderStatusPublic | null) {
  const metadata = objectRecord(providerStatus?.snapshot.source_metadata)
  return (
    stringValue(metadata.snapshot_id) ??
    providerStatus?.snapshot.id ??
    "No snapshot ID recorded"
  )
}

function _providerSelectedSources(providerStatus: ProviderStatusPublic | null) {
  const selected = providerStatus?.snapshot.selected_sources ?? []
  return selected.length > 0 ? selected.join(", ") : "No sources selected"
}

function _providerSourceHashes(providerStatus: ProviderStatusPublic | null) {
  const hashes = providerStatus?.snapshot.source_hashes ?? {}
  const values = Object.entries(hashes).map(([source, hash]) =>
    typeof hash === "string" && hash.trim()
      ? `${source}: ${hash}`
      : `${source}: N.A.`,
  )
  return values.length > 0 ? values.join(" | ") : "No source hashes recorded"
}

function _providerDataQualityNoticeItems(
  providerStatus: ProviderStatusPublic | null,
): DataQualityNoticeItem[] {
  return [
    ...providerDataQualityNotes(providerStatus).map((note) => ({
      detail: "Data quality note",
      label: "Provider evidence",
      message: note,
    })),
    ...(providerStatus?.warnings ?? []).map((warning) => ({
      detail: "Degraded evidence",
      label: "Warning",
      message: warning,
    })),
    ...(providerStatus?.last_error
      ? [
          {
            detail: "Provider update failure",
            label: "Last Error",
            message: providerStatus.last_error,
          },
        ]
      : []),
  ]
}

type WorkbenchShellProps = {
  findingDetailId?: string | null
  routePath: WorkbenchPath
}

export function WorkbenchShell({
  findingDetailId = null,
  routePath,
}: WorkbenchShellProps) {
  const navigate = useNavigate()
  const location = useLocation()
  const currentPath = routePath
  const isFindingDetail = findingDetailId !== null
  const isDashboard = currentPath === "/"
  const isFindingsList = currentPath === "/findings" && !isFindingDetail
  const isWaiversPage = currentPath === "/waivers"
  const findingSearchParams = new URLSearchParams(location.search)
  const findingAssetId = isFindingsList
    ? findingSearchParams.get("assetId")
    : null
  const findingAssetKey = isFindingsList
    ? findingSearchParams.get("assetKey")
    : null
  const routeDetail = routeDetails[currentPath]
  const [status, setStatus] = useState<WorkbenchStatus | null>(null)
  const [providerStatus, setProviderStatus] =
    useState<ProviderStatusPublic | null>(null)
  const [providerStatusLoading, setProviderStatusLoading] = useState(true)
  const [providerStatusError, setProviderStatusError] = useState("")
  const [currentUser, setCurrentUser] = useState<UserPublic | null>(null)
  const [statusError, setStatusError] = useState("")
  const [apiTokens, setApiTokens] = useState<ApiTokenPublic[]>([])
  const [apiTokensLoading, setApiTokensLoading] = useState(false)
  const [apiTokenActionLoading, setApiTokenActionLoading] = useState(false)
  const [apiTokenError, setApiTokenError] = useState("")
  const [apiTokenMessage, setApiTokenMessage] = useState("")
  const [apiTokenName, setApiTokenName] = useState("automation")
  const [apiTokenScopes, setApiTokenScopes] = useState<ApiTokenScope[]>(
    defaultApiTokenScopes,
  )
  const [createdApiToken, setCreatedApiToken] =
    useState<ApiTokenCreatePublic | null>(null)
  const [apiTokensReloadKey, setApiTokensReloadKey] = useState(0)
  const [projects, setProjects] = useState<ProjectPublic[]>([])
  const [selectedProjectId, setSelectedProjectId] = useState("")
  const [projectSummary, setProjectSummary] =
    useState<ProjectDecisionSummaryPublic | null>(null)
  const [projectSummaryById, setProjectSummaryById] = useState<
    Record<string, ProjectDecisionSummaryPublic>
  >({})
  const [projectAttackSummary, setProjectAttackSummary] =
    useState<ProjectAttackSummaryPublic | null>(null)
  const [projectGovernanceRollups, setProjectGovernanceRollups] =
    useState<ProjectGovernanceRollupsPublic | null>(null)
  const [projectListLoading, setProjectListLoading] = useState(true)
  const [summaryLoading, setSummaryLoading] = useState(false)
  const [attackSummaryLoading, setAttackSummaryLoading] = useState(false)
  const [attackSummaryError, setAttackSummaryError] = useState("")
  const [governanceLoading, setGovernanceLoading] = useState(false)
  const [governanceError, setGovernanceError] = useState("")
  const [dashboardError, setDashboardError] = useState("")
  const [createProjectForm, setCreateProjectForm] =
    useState<ProjectFormState>(emptyProjectForm)
  const [createProjectError, setCreateProjectError] = useState("")
  const [projectActionError, setProjectActionError] = useState("")
  const [projectActionMessage, setProjectActionMessage] = useState("")
  const [projectActionLoading, setProjectActionLoading] = useState(false)
  const [editProjectId, setEditProjectId] = useState("")
  const [editProjectForm, setEditProjectForm] =
    useState<ProjectFormState>(emptyProjectForm)
  const [deleteConfirmed, setDeleteConfirmed] = useState(false)
  const [importWizard, setImportWizard] = useState<ImportWizardState>(
    defaultImportWizardState,
  )
  const [importLoading, setImportLoading] = useState(false)
  const [importError, setImportError] = useState("")
  const [importRun, setImportRun] = useState<AnalysisRunPublic | null>(null)
  const [importRunSummary, setImportRunSummary] =
    useState<AnalysisRunSummaryPublic | null>(null)
  const [importParseErrors, setImportParseErrors] = useState<
    ImportParseErrorPublic[]
  >([])
  const [projectRuns, setProjectRuns] = useState<AnalysisRunPublic[]>([])
  const [runsLoading, setRunsLoading] = useState(false)
  const [runsError, setRunsError] = useState("")
  const [selectedRunId, setSelectedRunId] = useState("")
  const [selectedRun, setSelectedRun] = useState<AnalysisRunPublic | null>(null)
  const [selectedRunSummary, setSelectedRunSummary] =
    useState<AnalysisRunSummaryPublic | null>(null)
  const [runDetailLoading, setRunDetailLoading] = useState(false)
  const [runDetailError, setRunDetailError] = useState("")
  const [reports, setReports] = useState<ReportPublic[]>([])
  const [reportsLoading, setReportsLoading] = useState(false)
  const [reportsError, setReportsError] = useState("")
  const [_verificationReport, setVerificationReport] =
    useState<ReportVerificationPublic | null>(null)
  const [_verificationReportTarget, setVerificationReportTarget] =
    useState<ReportPublic | null>(null)
  const [_verificationLoading, setVerificationLoading] = useState(false)
  const [reportActionMessage, setReportActionMessage] = useState("")
  const [reportActionError, setReportActionError] = useState("")
  const [activeReportFormat, setActiveReportFormat] = useState<
    TemplateReportFormat | ""
  >("")
  const [reportsReloadKey, setReportsReloadKey] = useState(0)
  const [findings, setFindings] = useState<FindingPublic[]>([])
  const [findingCount, setFindingCount] = useState(0)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const [findingsError, setFindingsError] = useState("")
  const [dashboardFindings, setDashboardFindings] = useState<FindingPublic[]>(
    [],
  )
  const [dashboardFindingsLoading, setDashboardFindingsLoading] =
    useState(false)
  const [dashboardFindingsError, setDashboardFindingsError] = useState("")
  const [dashboardSignalCounts, setDashboardSignalCounts] =
    useState<DashboardSignalCounts>({
      highEpss: 0,
      internetFacingCriticals: 0,
      epssBuckets: {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
      },
    })
  const [dashboardSignalLoading, setDashboardSignalLoading] = useState(false)
  const [dashboardSignalError, setDashboardSignalError] = useState("")
  const [findingFilters, setFindingFilters] = useState<FindingFilters>(
    defaultFindingFilters,
  )
  const [findingSort, setFindingSort] = useState<FindingsSort>("operational")
  const [findingDirection, setFindingDirection] =
    useState<FindingsDirection>("asc")
  const [findingPageSize, setFindingPageSize] =
    useState<(typeof findingPageSizes)[number]>(10)
  const [findingOffset, setFindingOffset] = useState(0)
  const [findingReloadKey, setFindingReloadKey] = useState(0)
  const [findingDetail, setFindingDetail] =
    useState<FindingDetailPublic | null>(null)
  const [findingExplanation, setFindingExplanation] =
    useState<FindingExplanationPublic | null>(null)
  const [findingDetailLoading, setFindingDetailLoading] = useState(false)
  const [findingDetailError, setFindingDetailError] = useState("")
  const [findingExplanationWarning, setFindingExplanationWarning] = useState("")
  const [findingDetailReloadKey, setFindingDetailReloadKey] = useState(0)
  const [findingDetailTab, setFindingDetailTab] =
    useState<FindingDetailTab>("evidence")
  const [waivers, setWaivers] = useState<WaiverPublic[]>([])
  const [waiversLoading, setWaiversLoading] = useState(false)
  const [waiversError, setWaiversError] = useState("")
  const [waiverActionError, setWaiverActionError] = useState("")
  const [waiverActionMessage, setWaiverActionMessage] = useState("")
  const [waiverActionLoading, setWaiverActionLoading] = useState(false)
  const [waiverReloadKey, setWaiverReloadKey] = useState(0)
  const [waiverForm, setWaiverForm] =
    useState<WaiverFormState>(waiverFormDefaults)
  const selectedProject =
    projects.find((project) => project.id === selectedProjectId) ?? null
  const _selectedProjectSummary = selectedProjectId
    ? (projectSummaryById[selectedProjectId] ?? null)
    : null
  const _selectProjectForContext = (projectId: string) => {
    setSelectedProjectId(projectId)
    setDeleteConfirmed(false)
    setEditProjectId("")
  }
  const dashboardLoading = projectListLoading || summaryLoading
  const _dashboardCards = buildDashboardCards(
    projectSummary,
    providerStatus,
    dashboardLoading,
    dashboardSignalLoading || dashboardSignalError !== "",
    dashboardSignalCounts,
  )
  const _providerFreshness = formatProviderFreshness(providerStatus)
  const _isDashboardProviderStale =
    !dashboardLoading &&
    providerStatus !== null &&
    (providerStatus.status !== "ok" ||
      projectSummary?.provider_degraded === true)
  const summaryRows = buildSummaryRows(projectSummary)
  const attackRows = attackSummaryRows(projectAttackSummary)
  const attackTopTechniques = projectAttackSummary?.top_techniques ?? []
  const topServiceRows = governanceServiceRows(projectGovernanceRollups)
  const topServiceChartRows = topServiceRows.rows
  const topServiceSource = topServiceRows.source
  const priorityChartItems = findingsByPriorityChartData(projectSummary)
  const topServiceChartItems = topServicesByRiskChartData(topServiceChartRows)
  const runActivityItems = runActivityTrendData(projectRuns)
  const epssBucketItems = epssBucketChartData(dashboardSignalCounts.epssBuckets)
  const latestProjectRun = projectRuns[0] ?? null
  const waiverDebtSummary = waiverDebtSummaryRows(projectGovernanceRollups)
  const waiverDebtItems = waiverDebtRows(projectGovernanceRollups)
  const _findingPageStart =
    findingCount === 0 ? 0 : Math.min(findingOffset + 1, findingCount)
  const _findingPageEnd = Math.min(
    findingOffset + findings.length,
    findingCount,
  )
  const activeFindingFilters =
    hasActiveFindingFilters(findingFilters) || Boolean(findingAssetId)
  const detailOccurrences = findingOccurrenceRows(
    findingDetail,
    findingExplanation,
  )
  const detailDataQualityRows = findingDataQualityRows(
    findingDetail,
    findingExplanation,
  )
  const detailProviderGaps = findingProviderGaps(
    findingDetail,
    findingExplanation,
  )
  const detailReasonRows = findingReasonRows(findingExplanation)
  const detailAttackContext = findingDetail?.attack_context ?? null
  const detailAttackTechniques = attackTechniqueRows(detailAttackContext)
  const detailAttackPrimaryTechnique = detailAttackTechniques[0] ?? null
  const detailAttackActionItems = defensiveActionItems(
    detailAttackPrimaryTechnique?.defensive_note,
  )
  const detailAttackCoverageStatus =
    attackCoverageStatusLabel(detailAttackContext)
  const detailAttackTacticLabel = attackTacticsLabel(
    detailAttackPrimaryTechnique?.tactics ?? detailAttackContext?.tactics,
  )
  const detailAttackTechniqueId =
    detailAttackPrimaryTechnique?.technique_id ?? "Technique"
  const detailAttackTechniqueName =
    detailAttackPrimaryTechnique?.name ?? "Technique"
  const detailAttackTechniqueLabel = `${detailAttackTechniqueId} ${detailAttackTechniqueName}`
  const detailAttackSource = attackSourceLabel(
    detailAttackPrimaryTechnique?.source ?? detailAttackContext?.source,
    detailAttackContext,
  )
  const detailAttackRationale =
    detailAttackPrimaryTechnique?.rationale ?? detailAttackContext?.rationale
  const detailAttackEmpty = attackContextEmptyState(detailAttackContext)
  const detailWaiverEvidence = findingWaiverEvidence(findingDetail)
  const detailDecisionReasons = findingDecisionReasonRows(
    findingDetail,
    findingExplanation,
    detailAttackContext,
  )
  const detailEvidenceRows = findingEvidenceRows(
    findingDetail,
    findingExplanation,
    detailOccurrences,
    detailDataQualityRows,
    detailProviderGaps,
  )
  const detailHistoryRows = findingHistoryRows(
    findingDetail,
    detailOccurrences,
    detailWaiverEvidence,
  )
  const isDemoFindingDetail = Boolean(
    findingDetail &&
      (findingDetail.project_id === DEMO_PROJECT.id ||
        findingDetail.id.startsWith("demo-")),
  )
  const selectedReportRun =
    projectRuns.find((run) => run.id === selectedRunId) ?? null
  const reportActionsEnabled =
    currentPath === "/reports" &&
    Boolean(selectedReportRun) &&
    isReportableRun(selectedReportRun) &&
    !reportsLoading

  useEffect(() => {
    if (currentPath !== "/settings") {
      setCreatedApiToken(null)
    }
  }, [currentPath])

  useEffect(() => {
    let isMounted = true

    async function loadTemplateState() {
      setProviderStatusLoading(true)
      try {
        const [workbenchStatus, providerStatusResponse, user] =
          await Promise.all([
            WorkbenchService.templateWorkbenchStatus(),
            ProvidersService.readProviderStatus(),
            UsersService.readUserMe(),
          ])
        if (isMounted) {
          setStatus(workbenchStatus)
          setProviderStatus(providerStatusResponse)
          setCurrentUser(user)
          setStatusError("")
          setProviderStatusError("")
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setStatusError("Data services unavailable")
          setProviderStatusError(
            apiErrorMessage("Provider status unavailable", caught),
          )
        }
      } finally {
        if (isMounted) {
          setProviderStatusLoading(false)
        }
      }
    }

    void loadTemplateState()
    return () => {
      isMounted = false
    }
  }, [navigate])

  useEffect(() => {
    let isMounted = true

    async function loadProjects() {
      setProjectListLoading(true)
      setDashboardError("")
      try {
        const projectPage = await ProjectsService.readProjects()
        if (isMounted) {
          setProjects(projectPage.data)
          setSelectedProjectId((previousProjectId) =>
            projectPage.data.some((project) => project.id === previousProjectId)
              ? previousProjectId
              : (projectPage.data[0]?.id ?? ""),
          )
          if (projectPage.data.length === 0) {
            setProjectSummary(null)
            setProjectAttackSummary(null)
          }
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setProjects([])
          setSelectedProjectId("")
          setProjectSummary(null)
          setProjectAttackSummary(null)
          setDashboardError(apiErrorMessage("Project list unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setProjectListLoading(false)
        }
      }
    }

    void loadProjects()
    return () => {
      isMounted = false
    }
  }, [navigate])

  useEffect(() => {
    let isMounted = true

    async function loadProjectSummaries() {
      if (projects.length === 0) {
        setProjectSummaryById({})
        return
      }
      const entries = await Promise.allSettled(
        projects.map((project) =>
          ProjectsService.readProjectSummary({ project_id: project.id }),
        ),
      )
      if (!isMounted) {
        return
      }
      const summaryMap: Record<string, ProjectDecisionSummaryPublic> = {}
      entries.forEach((entry, index) => {
        if (entry.status !== "fulfilled") {
          return
        }
        summaryMap[projects[index].id] = entry.value
      })
      setProjectSummaryById(summaryMap)
    }

    void loadProjectSummaries()
    return () => {
      isMounted = false
    }
  }, [projects])

  useEffect(() => {
    let isMounted = true

    async function loadApiTokens() {
      if (currentPath !== "/settings") {
        return
      }
      setApiTokensLoading(true)
      setApiTokenError("")
      try {
        const response = await ApiTokensService.listApiTokens()
        if (isMounted) {
          setApiTokens(response.data)
        }
      } catch (caught) {
        if (caught instanceof ApiError && caught.status === 401) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setApiTokens([])
          setApiTokenError(apiErrorMessage("API tokens unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setApiTokensLoading(false)
        }
      }
    }

    void loadApiTokens()
    return () => {
      isMounted = false
    }
  }, [apiTokensReloadKey, currentPath, navigate])

  useEffect(() => {
    let isMounted = true

    async function loadProjectSummary() {
      if (!selectedProjectId) {
        setProjectSummary(null)
        setSummaryLoading(false)
        return
      }

      setSummaryLoading(true)
      setDashboardError("")
      try {
        const summary = await ProjectsService.readProjectSummary({
          project_id: selectedProjectId,
        })
        if (isMounted) {
          setProjectSummary(summary)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setProjectSummary(null)
          setDashboardError(
            apiErrorMessage("Project summary unavailable", caught),
          )
        }
      } finally {
        if (isMounted) {
          setSummaryLoading(false)
        }
      }
    }

    void loadProjectSummary()
    return () => {
      isMounted = false
    }
  }, [navigate, selectedProjectId, waiverReloadKey])

  useEffect(() => {
    let isMounted = true

    async function loadProjectAttackSummary() {
      if (!selectedProjectId) {
        setProjectAttackSummary(null)
        setAttackSummaryError("")
        setAttackSummaryLoading(false)
        return
      }

      setAttackSummaryLoading(true)
      setAttackSummaryError("")
      try {
        const attackSummary = await ProjectsService.readProjectAttackSummary({
          project_id: selectedProjectId,
        })
        if (isMounted) {
          setProjectAttackSummary(attackSummary)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setProjectAttackSummary(null)
          setAttackSummaryError(
            apiErrorMessage("ATT&CK summary unavailable", caught),
          )
        }
      } finally {
        if (isMounted) {
          setAttackSummaryLoading(false)
        }
      }
    }

    void loadProjectAttackSummary()
    return () => {
      isMounted = false
    }
  }, [navigate, selectedProjectId])

  useEffect(() => {
    let isMounted = true

    async function loadProjectGovernanceRollups() {
      if (!selectedProjectId) {
        setProjectGovernanceRollups(null)
        setGovernanceError("")
        setGovernanceLoading(false)
        return
      }

      setGovernanceLoading(true)
      setGovernanceError("")
      try {
        const rollups = await ProjectsService.readProjectGovernanceRollups({
          project_id: selectedProjectId,
          limit: 5,
        })
        if (isMounted) {
          setProjectGovernanceRollups(rollups)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setProjectGovernanceRollups(null)
          setGovernanceError(
            apiErrorMessage("Governance rollups unavailable", caught),
          )
        }
      } finally {
        if (isMounted) {
          setGovernanceLoading(false)
        }
      }
    }

    void loadProjectGovernanceRollups()
    return () => {
      isMounted = false
    }
  }, [navigate, selectedProjectId, waiverReloadKey])

  useEffect(() => {
    let isMounted = true

    async function loadProjectRuns() {
      if (
        !["/", "/imports", "/reports"].includes(currentPath) ||
        !selectedProjectId
      ) {
        setProjectRuns([])
        setSelectedRunId("")
        setRunsError("")
        setRunsLoading(false)
        return
      }

      setRunsLoading(true)
      setRunsError("")
      try {
        const runPage = await RunsService.readProjectRuns({
          project_id: selectedProjectId,
        })
        if (isMounted) {
          setProjectRuns(runPage.data)
          setSelectedRunId((currentRunId) =>
            runPage.data.some((run) => run.id === currentRunId)
              ? currentRunId
              : (runPage.data[0]?.id ?? ""),
          )
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setProjectRuns([])
          setSelectedRunId("")
          setRunsError(apiErrorMessage("Import runs unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setRunsLoading(false)
        }
      }
    }

    void loadProjectRuns()
    return () => {
      isMounted = false
    }
  }, [currentPath, navigate, selectedProjectId])

  useEffect(() => {
    let isMounted = true

    async function loadRunReports() {
      if (currentPath !== "/reports" || !selectedRunId) {
        setReports([])
        setReportsError("")
        setReportsLoading(false)
        setVerificationReport(null)
        setVerificationReportTarget(null)
        return
      }

      setReportsLoading(true)
      setReportsError("")
      setVerificationReport(null)
      setVerificationReportTarget(null)
      try {
        const reportPage = await ReportsService.readRunReports({
          run_id: selectedRunId,
        })
        if (isMounted) {
          setReports(reportPage.data)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setReports([])
          setReportsError(apiErrorMessage("Report history unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setReportsLoading(false)
        }
      }
    }

    void loadRunReports()
    return () => {
      isMounted = false
    }
  }, [currentPath, navigate, reportsReloadKey, selectedRunId])

  useEffect(() => {
    let isMounted = true

    async function loadRunDetail() {
      if (!["/imports", "/reports"].includes(currentPath) || !selectedRunId) {
        setSelectedRun(null)
        setSelectedRunSummary(null)
        setRunDetailError("")
        setRunDetailLoading(false)
        return
      }

      setRunDetailLoading(true)
      setRunDetailError("")
      try {
        const [run, summary] = await Promise.all([
          RunsService.readRun({ run_id: selectedRunId }),
          RunsService.readRunSummary({ run_id: selectedRunId }),
        ])
        if (isMounted) {
          setSelectedRun(run)
          setSelectedRunSummary(summary)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setSelectedRun(null)
          setSelectedRunSummary(null)
          setRunDetailError(apiErrorMessage("Run detail unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setRunDetailLoading(false)
        }
      }
    }

    void loadRunDetail()
    return () => {
      isMounted = false
    }
  }, [currentPath, navigate, selectedRunId])

  useEffect(() => {
    let isMounted = true

    async function loadProjectWaivers() {
      if (!isWaiversPage || !selectedProjectId) {
        setWaivers([])
        setWaiversError("")
        setWaiversLoading(false)
        return
      }

      setWaiversLoading(true)
      setWaiversError("")
      try {
        const page = await WaiversService.readProjectWaivers({
          project_id: selectedProjectId,
        })
        if (isMounted) {
          setWaivers(page.data)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setWaivers([])
          setWaiversError(apiErrorMessage("Waivers unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setWaiversLoading(false)
        }
      }
    }

    void loadProjectWaivers()
    return () => {
      isMounted = false
    }
  }, [isWaiversPage, navigate, selectedProjectId, waiverReloadKey])

  useEffect(() => {
    let isMounted = true

    async function loadFindingsPage() {
      if (!isFindingsList || !selectedProjectId) {
        setFindings([])
        setFindingCount(0)
        setFindingsError("")
        setFindingsLoading(false)
        return
      }

      setFindingsLoading(true)
      setFindingsError("")
      try {
        const page = await FindingsService.readProjectFindings({
          cvss_max: numericFilterValue(findingFilters.cvssMax),
          cvss_min: numericFilterValue(findingFilters.cvssMin),
          direction: findingDirection,
          epss_max: numericFilterValue(findingFilters.epssMax),
          epss_min: numericFilterValue(findingFilters.epssMin),
          exposure: findingFilters.exposure || undefined,
          kev:
            findingFilters.kev === ""
              ? undefined
              : findingFilters.kev === "true",
          limit: findingPageSize,
          offset: findingOffset,
          asset_id: findingAssetId || undefined,
          owner_service: findingFilters.ownerService.trim() || undefined,
          priority: findingFilters.priority || undefined,
          project_id: selectedProjectId,
          sort: findingSort,
          status: findingFilters.status || undefined,
        })
        if (isMounted) {
          setFindings(page.data)
          setFindingCount(page.count)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setFindings([])
          setFindingCount(0)
          setFindingsError(apiErrorMessage("Findings unavailable", caught))
        }
      } finally {
        if (isMounted) {
          setFindingsLoading(false)
        }
      }
    }

    void loadFindingsPage()
    return () => {
      isMounted = false
    }
  }, [
    findingDirection,
    findingFilters.cvssMax,
    findingFilters.cvssMin,
    findingFilters.epssMax,
    findingFilters.epssMin,
    findingFilters.exposure,
    findingFilters.kev,
    findingFilters.ownerService,
    findingFilters.priority,
    findingFilters.status,
    findingOffset,
    findingPageSize,
    findingReloadKey,
    findingSort,
    findingAssetId,
    isFindingsList,
    navigate,
    selectedProjectId,
  ])

  useEffect(() => {
    let isMounted = true

    async function loadDashboardFindings() {
      if (!isDashboard || !selectedProjectId) {
        setDashboardFindings([])
        setDashboardFindingsError("")
        setDashboardFindingsLoading(false)
        return
      }

      setDashboardFindingsLoading(true)
      setDashboardFindingsError("")
      try {
        const page = await FindingsService.readProjectFindings({
          direction: "asc",
          limit: 5,
          offset: 0,
          project_id: selectedProjectId,
          sort: "operational",
        })
        if (isMounted) {
          setDashboardFindings(page.data)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setDashboardFindings([])
          setDashboardFindingsError(
            apiErrorMessage("Remediation queue unavailable", caught),
          )
        }
      } finally {
        if (isMounted) {
          setDashboardFindingsLoading(false)
        }
      }
    }

    void loadDashboardFindings()
    return () => {
      isMounted = false
    }
  }, [findingReloadKey, isDashboard, navigate, selectedProjectId])

  useEffect(() => {
    let isMounted = true

    async function loadDashboardSignals() {
      if (!isDashboard || !selectedProjectId) {
        setDashboardSignalCounts({
          highEpss: 0,
          internetFacingCriticals: 0,
          epssBuckets: {
            low: 0,
            medium: 0,
            high: 0,
            critical: 0,
          },
        })
        setDashboardSignalError("")
        setDashboardSignalLoading(false)
        return
      }

      setDashboardSignalLoading(true)
      setDashboardSignalError("")
      try {
        const [
          highEpssPage,
          internetFacingCriticalPage,
          epssLowPage,
          epssMediumPage,
          epssHighPage,
          epssCriticalPage,
        ] = await Promise.all([
          FindingsService.readProjectFindings({
            direction: "desc",
            epss_min: 0.7,
            limit: 1,
            offset: 0,
            project_id: selectedProjectId,
            sort: "operational",
          }),
          FindingsService.readProjectFindings({
            direction: "desc",
            exposure: "internet-facing",
            limit: 1,
            offset: 0,
            priority: "critical",
            project_id: selectedProjectId,
            sort: "operational",
          }),
          FindingsService.readProjectFindings({
            direction: "desc",
            epss_max: 0.25,
            epss_min: 0,
            limit: 1,
            offset: 0,
            project_id: selectedProjectId,
            sort: "operational",
          }),
          FindingsService.readProjectFindings({
            direction: "desc",
            epss_max: 0.5,
            epss_min: 0.25,
            limit: 1,
            offset: 0,
            project_id: selectedProjectId,
            sort: "operational",
          }),
          FindingsService.readProjectFindings({
            direction: "desc",
            epss_max: 0.7,
            epss_min: 0.5,
            limit: 1,
            offset: 0,
            project_id: selectedProjectId,
            sort: "operational",
          }),
          FindingsService.readProjectFindings({
            direction: "desc",
            epss_min: 0.7,
            limit: 1,
            offset: 0,
            project_id: selectedProjectId,
            sort: "operational",
          }),
        ])
        if (isMounted) {
          setDashboardSignalCounts({
            highEpss: highEpssPage.count ?? 0,
            internetFacingCriticals: internetFacingCriticalPage.count ?? 0,
            epssBuckets: {
              low: epssLowPage.count ?? 0,
              medium: epssMediumPage.count ?? 0,
              high: epssHighPage.count ?? 0,
              critical: epssCriticalPage.count ?? 0,
            },
          })
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setDashboardSignalError(
            apiErrorMessage("Signal counts unavailable", caught),
          )
          setDashboardSignalCounts({
            highEpss: 0,
            internetFacingCriticals: 0,
            epssBuckets: {
              low: 0,
              medium: 0,
              high: 0,
              critical: 0,
            },
          })
        }
      } finally {
        if (isMounted) {
          setDashboardSignalLoading(false)
        }
      }
    }

    void loadDashboardSignals()
    return () => {
      isMounted = false
    }
  }, [findingReloadKey, isDashboard, navigate, selectedProjectId])

  useEffect(() => {
    setFindingDetailTab("evidence")
  }, [findingDetailId])

  useEffect(() => {
    let isMounted = true

    async function loadFindingDetail() {
      if (!findingDetailId) {
        setFindingDetail(null)
        setFindingExplanation(null)
        setFindingDetailError("")
        setFindingExplanationWarning("")
        setFindingDetailLoading(false)
        return
      }

      setFindingDetailLoading(true)
      setFindingDetailError("")
      setFindingExplanationWarning("")
      const demoDetail = demoFindingDetailForId(findingDetailId)
      if (demoDetail) {
        if (isMounted) {
          setFindingDetail(demoDetail)
          setFindingExplanation(demoFindingExplanationForDetail(demoDetail))
          setFindingDetailLoading(false)
        }
        return
      }
      try {
        const detail = await FindingsService.readFinding({
          finding_id: findingDetailId,
        })
        let explanation: FindingExplanationPublic | null = null
        let explanationWarning = ""
        try {
          explanation = await FindingsService.explainFinding({
            finding_id: findingDetailId,
          })
        } catch (caught) {
          if (caught instanceof ApiError && caught.status === 422) {
            explanationWarning = apiErrorMessage(
              "Priority explanation unavailable",
              caught,
            )
          } else {
            throw caught
          }
        }
        if (isMounted) {
          setFindingDetail(detail)
          setFindingExplanation(explanation)
          setFindingExplanationWarning(explanationWarning)
          setSelectedProjectId(detail.project_id)
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setFindingDetail(null)
          setFindingExplanation(null)
          setFindingDetailError(
            apiErrorMessage("Finding detail unavailable", caught),
          )
        }
      } finally {
        if (isMounted) {
          setFindingDetailLoading(false)
        }
      }
    }

    void loadFindingDetail()
    return () => {
      isMounted = false
    }
  }, [findingDetailId, findingDetailReloadKey, navigate])

  function selectProject(projectId: string) {
    setSelectedProjectId(projectId)
    setDeleteConfirmed(false)
    setEditProjectId("")
  }

  function _openProjectRoute(projectId: string, destination: string) {
    selectProject(projectId)
    void navigate({ to: destination })
  }

  async function refreshProjects(preferredProjectId?: string) {
    const projectPage = await ProjectsService.readProjects()
    setProjects(projectPage.data)
    setSelectedProjectId((previousProjectId) => {
      if (
        preferredProjectId &&
        projectPage.data.some((project) => project.id === preferredProjectId)
      ) {
        return preferredProjectId
      }
      if (
        projectPage.data.some((project) => project.id === previousProjectId)
      ) {
        return previousProjectId
      }
      return projectPage.data[0]?.id ?? ""
    })
    if (projectPage.data.length === 0) {
      setProjectSummary(null)
    }
  }

  async function refreshProviderStatus() {
    setProviderStatusLoading(true)
    setProviderStatusError("")
    try {
      const statusResponse = await ProvidersService.readProviderStatus()
      setProviderStatus(statusResponse)
    } catch (caught) {
      if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
        clearAccessToken()
        await navigate({ to: "/login" })
        return
      }
      setProviderStatusError(
        apiErrorMessage("Provider status unavailable", caught),
      )
    } finally {
      setProviderStatusLoading(false)
    }
  }

  async function refreshProjectRuns(preferredRunId?: string) {
    if (!selectedProjectId) {
      setProjectRuns([])
      setSelectedRunId("")
      return
    }
    setRunsLoading(true)
    setRunsError("")
    try {
      const runPage = await RunsService.readProjectRuns({
        project_id: selectedProjectId,
      })
      setProjectRuns(runPage.data)
      setSelectedRunId((currentRunId) => {
        if (
          preferredRunId &&
          runPage.data.some((run) => run.id === preferredRunId)
        ) {
          return preferredRunId
        }
        if (runPage.data.some((run) => run.id === currentRunId)) {
          return currentRunId
        }
        return runPage.data[0]?.id ?? ""
      })
    } catch (caught) {
      if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
        clearAccessToken()
        await navigate({ to: "/login" })
        return
      }
      setProjectRuns([])
      setSelectedRunId("")
      setRunsError(apiErrorMessage("Import runs unavailable", caught))
    } finally {
      setRunsLoading(false)
    }
  }

  function updateFindingFilter<Key extends keyof FindingFilters>(
    key: Key,
    value: FindingFilters[Key],
  ) {
    setFindingOffset(0)
    setFindingFilters((filters) => ({ ...filters, [key]: value }))
  }

  function clearFindingFilters() {
    setFindingOffset(0)
    setFindingFilters(defaultFindingFilters)
    if (findingAssetId) {
      void navigate({ to: "/findings" })
    }
  }

  function updateFindingSort(sort: FindingsSort) {
    setFindingOffset(0)
    setFindingSort(sort)
  }

  function updateFindingDirection(direction: FindingsDirection) {
    setFindingOffset(0)
    setFindingDirection(direction)
  }

  function _updateFindingPageSize(size: number) {
    const supportedSize = findingPageSizes.includes(
      size as (typeof findingPageSizes)[number],
    )
      ? (size as (typeof findingPageSizes)[number])
      : 10
    setFindingOffset(0)
    setFindingPageSize(supportedSize)
  }

  function refreshFindings() {
    setFindingReloadKey((key) => key + 1)
  }

  function refreshFindingDetail() {
    setFindingDetailReloadKey((key) => key + 1)
  }

  function _refreshReports() {
    setReportsReloadKey((key) => key + 1)
  }

  async function createReport(format: TemplateReportFormat) {
    if (!selectedRunId) {
      setReportActionError(
        "Select a completed analysis run before generating reports.",
      )
      return
    }
    setReportActionError("")
    setReportActionMessage("")
    setActiveReportFormat(format)
    try {
      const report = await ReportsService.createRunReport({
        run_id: selectedRunId,
        reportCreate: { format },
      })
      setReports((currentReports) => [report, ...currentReports])
      setReportActionMessage(
        `${reportFormatLabel(report.format)} report generated as ${report.filename}.`,
      )
    } catch (caught) {
      setReportActionError(apiErrorMessage("Report generation failed", caught))
    } finally {
      setActiveReportFormat("")
    }
  }

  async function downloadReport(report: ReportPublic) {
    setReportActionError("")
    setReportActionMessage("")
    try {
      await downloadReportArtifact(report)
      setReportActionMessage(`Download started for ${report.filename}.`)
    } catch (caught) {
      setReportActionError(
        caught instanceof Error
          ? `Report download failed: ${caught.message}`
          : "Report download failed: unexpected client error",
      )
    }
  }

  async function verifyEvidenceReport(report: ReportPublic) {
    setVerificationLoading(true)
    setVerificationReport(null)
    setVerificationReportTarget(report)
    setReportActionError("")
    setReportActionMessage("")
    try {
      const verification = await ReportsService.verifyReport({
        report_id: report.id,
      })
      setVerificationReport(verification)
      const summary = objectRecord(verification.summary)
      setReportActionMessage(
        summary.ok
          ? `Evidence bundle verified: ${summary.verified_files ?? 0} files matched.`
          : `Evidence bundle verification failed: ${summary.modified_files ?? 0} modified, ${summary.missing_files ?? 0} missing.`,
      )
    } catch (caught) {
      setReportActionError(
        apiErrorMessage("Evidence verification failed", caught),
      )
      setVerificationReport(null)
      setVerificationReportTarget(null)
    } finally {
      setVerificationLoading(false)
    }
  }

  async function createProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setCreateProjectError("")
    setProjectActionError("")
    setProjectActionMessage("")
    const validationError = validateProjectForm(createProjectForm)
    if (validationError) {
      setCreateProjectError(validationError)
      return
    }

    setProjectActionLoading(true)
    try {
      const project = await ProjectsService.createProject({
        projectCreate: projectRequestBody(createProjectForm),
      })
      setCreateProjectForm(emptyProjectForm)
      setProjectActionMessage(`Project ${project.name} created.`)
      await refreshProjects(project.id)
    } catch (caught) {
      setProjectActionError(apiErrorMessage("Project create failed", caught))
    } finally {
      setProjectActionLoading(false)
    }
  }

  function startEditProject(project: ProjectPublic) {
    setEditProjectId(project.id)
    setEditProjectForm({
      description: project.description ?? "",
      name: project.name,
    })
    setDeleteConfirmed(false)
    setProjectActionError("")
    setProjectActionMessage("")
  }

  async function saveProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!editProjectId) {
      return
    }
    setProjectActionError("")
    setProjectActionMessage("")
    const validationError = validateProjectForm(editProjectForm)
    if (validationError) {
      setProjectActionError(validationError)
      return
    }

    setProjectActionLoading(true)
    try {
      const project = await ProjectsService.updateProject({
        project_id: editProjectId,
        projectUpdate: projectRequestBody(editProjectForm),
      })
      setEditProjectId("")
      setProjectActionMessage(`Project ${project.name} updated.`)
      await refreshProjects(project.id)
    } catch (caught) {
      setProjectActionError(apiErrorMessage("Project update failed", caught))
    } finally {
      setProjectActionLoading(false)
    }
  }

  async function deleteProject(project: ProjectPublic) {
    if (!deleteConfirmed) {
      setProjectActionError("Confirm deletion before deleting this project.")
      return
    }

    setProjectActionLoading(true)
    setProjectActionError("")
    setProjectActionMessage("")
    try {
      await ProjectsService.deleteProject({ project_id: project.id })
      setDeleteConfirmed(false)
      setEditProjectId("")
      setProjectActionMessage(`Project ${project.name} deleted.`)
      await refreshProjects()
    } catch (caught) {
      setProjectActionError(apiErrorMessage("Project delete failed", caught))
    } finally {
      setProjectActionLoading(false)
    }
  }

  async function submitImport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formData = new FormData(event.currentTarget)
    const formFile = formData.get("importFile")
    const formAssetContextFile = formData.get("assetContextFile")
    const formVexFile = formData.get("vexFile")
    const formProjectId = formData.get("importProject")
    const importProjectId =
      typeof formProjectId === "string" && formProjectId.trim()
        ? formProjectId
        : selectedProjectId
    const selectedFile =
      importWizard.file ??
      (formFile instanceof File && formFile.size > 0 ? formFile : null)
    const selectedAssetContextFile =
      importWizard.assetContextFile ??
      (formAssetContextFile instanceof File && formAssetContextFile.size > 0
        ? formAssetContextFile
        : null)
    const selectedVexFile =
      importWizard.vexFile ??
      (formVexFile instanceof File && formVexFile.size > 0 ? formVexFile : null)
    setImportError("")
    setImportRun(null)
    setImportRunSummary(null)
    setImportParseErrors([])
    if (!importProjectId) {
      setImportError("Select or create a project before uploading.")
      return
    }
    if (!selectedFile) {
      setImportError("Choose an import file before uploading.")
      return
    }

    setImportLoading(true)
    try {
      setSelectedProjectId(importProjectId)
      const uploadFormData: ImportUploadFormData = {
        ...(selectedAssetContextFile
          ? {
              asset_context_file: selectedAssetContextFile,
            }
          : {}),
        ...(selectedVexFile
          ? {
              vex_file: selectedVexFile,
            }
          : {}),
        file: selectedFile,
        input_type: importWizard.inputType,
      }
      const run = await ImportsService.importProjectUpload({
        project_id: importProjectId,
        bodyImportsImportProjectUpload: uploadFormData,
      })
      setImportRun(run)
      const summary = await RunsService.readRunSummary({ run_id: run.id })
      setImportRunSummary(summary)
      setImportParseErrors(summary.parse_errors ?? [])
      setSelectedRunId(run.id)
      await refreshProjects(importProjectId)
      await refreshProjectRuns(run.id)
    } catch (caught) {
      setImportError(apiErrorMessage("Import upload failed", caught))
      const runId = analysisRunIdFromError(caught)
      const parseErrors = parseErrorsFromError(caught)
      setImportParseErrors(parseErrors)
      if (runId) {
        setSelectedRunId(runId)
        try {
          const summary = await RunsService.readRunSummary({ run_id: runId })
          setImportRunSummary(summary)
          setImportParseErrors(summary.parse_errors ?? parseErrors)
        } catch {
          setImportRunSummary(null)
        }
      }
      await refreshProjects(importProjectId)
      await refreshProjectRuns(runId ?? undefined)
    } finally {
      setImportLoading(false)
    }
  }

  function refreshWaivers() {
    setWaiverReloadKey((key) => key + 1)
  }

  function updateWaiverFormField(field: keyof WaiverFormState, value: string) {
    setWaiverForm((form) => ({
      ...form,
      [field]: value,
    }))
  }

  async function createWaiver(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setWaiverActionError("")
    setWaiverActionMessage("")
    const validationError = validateWaiverForm(waiverForm)
    if (validationError) {
      setWaiverActionError(validationError)
      return
    }
    if (!selectedProjectId) {
      setWaiverActionError("Select a project before creating a waiver.")
      return
    }

    setWaiverActionLoading(true)
    try {
      const waiver = await WaiversService.createProjectWaiver({
        project_id: selectedProjectId,
        waiverCreate: waiverRequestBody(waiverForm),
      })
      setWaiverForm(waiverFormDefaults())
      setWaiverActionMessage(
        `Accepted risk waiver created for ${waiverScopeLabel(waiver)}.`,
      )
      refreshWaivers()
      refreshFindings()
      setFindingDetailReloadKey((key) => key + 1)
    } catch (caught) {
      setWaiverActionError(apiErrorMessage("Waiver create failed", caught))
    } finally {
      setWaiverActionLoading(false)
    }
  }

  async function expireWaiver(waiver: WaiverPublic) {
    setWaiverActionError("")
    setWaiverActionMessage("")
    setWaiverActionLoading(true)
    try {
      const expired = await WaiversService.expireWaiver({
        waiver_id: waiver.id,
      })
      setWaiverActionMessage(
        `Waiver for ${waiverScopeLabel(expired)} is now expired.`,
      )
      refreshWaivers()
      refreshFindings()
      setFindingDetailReloadKey((key) => key + 1)
    } catch (caught) {
      setWaiverActionError(apiErrorMessage("Waiver expire failed", caught))
    } finally {
      setWaiverActionLoading(false)
    }
  }

  function toggleApiTokenScope(scope: ApiTokenScope) {
    setApiTokenScopes((previousScopes) => {
      const nextScopes = previousScopes.includes(scope)
        ? previousScopes.filter((item) => item !== scope)
        : [...previousScopes, scope]
      return canonicalApiTokenScopes(nextScopes)
    })
  }

  async function createApiToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const name = apiTokenName.trim()
    if (!name) {
      setApiTokenError("Token name is required.")
      return
    }
    if (apiTokenScopes.length === 0) {
      setApiTokenError("Select at least one scope.")
      return
    }

    setApiTokenActionLoading(true)
    setApiTokenError("")
    setApiTokenMessage("")
    setCreatedApiToken(null)
    try {
      const created = await ApiTokensService.createApiToken({
        apiTokenCreate: { name, scopes: apiTokenScopes },
      })
      setCreatedApiToken(created)
      setApiTokenName("automation")
      setApiTokenScopes(defaultApiTokenScopes)
      setApiTokenMessage(`Token ${created.name} created.`)
      setApiTokensReloadKey((key) => key + 1)
    } catch (caught) {
      setApiTokenError(apiErrorMessage("API token create failed", caught))
    } finally {
      setApiTokenActionLoading(false)
    }
  }

  async function revokeApiToken(token: ApiTokenPublic) {
    setApiTokenActionLoading(true)
    setApiTokenError("")
    setApiTokenMessage("")
    try {
      const revoked = await ApiTokensService.revokeApiToken({
        token_id: token.id,
      })
      setCreatedApiToken((created) =>
        created?.id === revoked.id ? null : created,
      )
      setApiTokenMessage(`Token ${revoked.name} revoked.`)
      setApiTokensReloadKey((key) => key + 1)
    } catch (caught) {
      setApiTokenError(apiErrorMessage("API token revoke failed", caught))
    } finally {
      setApiTokenActionLoading(false)
    }
  }

  return (
    <ProductAppShell
      activePath={currentPath}
      currentUser={currentUser}
      eyebrow={routeDetail.eyebrow}
      hideStatusStrip={currentPath === "/" || isFindingsList || isFindingDetail}
      providerStatus={providerStatus}
      status={status}
      statusError={statusError}
      title={routeDetail.title}
    >
      <Suspense fallback={<LoadingSkeleton label="Loading Workbench route" />}>
        {currentPath === "/" ? (
          <RiskOperationsDashboard
            projects={projects}
            selectedProject={selectedProject}
            selectedProjectId={selectedProjectId}
            onProjectChange={setSelectedProjectId}
            projectListLoading={projectListLoading}
            projectSummary={projectSummary}
            summaryLoading={summaryLoading}
            providerStatus={providerStatus}
            providerStatusLoading={providerStatusLoading}
            providerStatusError={providerStatusError || statusError}
            signalCounts={dashboardSignalCounts}
            signalLoading={dashboardSignalLoading}
            signalError={dashboardSignalError}
            findings={dashboardFindings}
            findingsLoading={dashboardFindingsLoading}
            findingsError={dashboardFindingsError}
            epssBuckets={epssBucketItems}
            projectRuns={projectRuns}
            runsLoading={runsLoading}
            topServiceRows={topServiceChartRows}
            topServiceSource={topServiceSource}
            governanceLoading={governanceLoading}
            governanceError={governanceError}
            onRefresh={() => {
              void refreshProjects(selectedProjectId)
              refreshFindings()
            }}
          />
        ) : null}

        {isFindingsList ? (
          <section
            aria-label="Findings Remediation Queue"
            className="mx-auto w-full max-w-screen-2xl px-4 py-6 sm:px-6"
          >
            <RemediationQueue
              activeFindingFilters={activeFindingFilters}
              findingAssetId={findingAssetId}
              findingAssetKey={findingAssetKey}
              findingCount={findingCount}
              findingDirection={findingDirection}
              findingFilters={findingFilters}
              findingOffset={findingOffset}
              findingPageSize={findingPageSize}
              findingSort={findingSort}
              findings={findings}
              findingsError={findingsError}
              findingsLoading={findingsLoading}
              onClearFilters={clearFindingFilters}
              onDirectionChange={updateFindingDirection}
              onFilterChange={updateFindingFilter}
              onPageNext={() =>
                setFindingOffset((offset) => offset + findingPageSize)
              }
              onPagePrev={() =>
                setFindingOffset((offset) =>
                  Math.max(0, offset - findingPageSize),
                )
              }
              onPageSizeChange={(size) => {
                const s = findingPageSizes.includes(
                  size as (typeof findingPageSizes)[number],
                )
                  ? (size as (typeof findingPageSizes)[number])
                  : 10
                setFindingOffset(0)
                setFindingPageSize(s)
              }}
              onProjectChange={(id) => {
                setFindingOffset(0)
                setSelectedProjectId(id)
              }}
              onSortChange={updateFindingSort}
              projectListLoading={projectListLoading}
              projectSummary={projectSummary}
              projects={projects}
              selectedProject={selectedProject}
              selectedProjectId={selectedProjectId}
            />
          </section>
        ) : null}

        {currentPath !== "/" && !isFindingsList && (
          <section
            className={
              isFindingDetail
                ? "mx-auto w-full max-w-[2040px] px-4 py-6 sm:px-6 lg:px-8 xl:px-10 2xl:px-12"
                : currentPath === "/findings" ||
                    currentPath === "/waivers" ||
                    currentPath === "/providers" ||
                    currentPath === "/settings" ||
                    currentPath === "/projects" ||
                    currentPath === "/imports" ||
                    currentPath === "/reports"
                  ? "mx-auto w-full max-w-screen-2xl px-4 sm:px-6 py-6"
                  : "mx-auto w-full max-w-5xl px-4 sm:px-6 py-6"
            }
          >
            <div className="flex flex-col gap-6">
              {!isFindingsList &&
                !isFindingDetail &&
                currentPath !== "/projects" &&
                currentPath !== "/imports" &&
                currentPath !== "/reports" &&
                currentPath !== "/settings" &&
                currentPath !== "/providers" && (
                  <div className="flex items-start justify-between gap-4 pb-4 border-b">
                    <div>
                      <h2 className="text-xl font-bold tracking-tight text-foreground">
                        {isFindingDetail
                          ? "Finding Detail"
                          : routeDetail.panelTitle}
                      </h2>
                      <p className="mt-0.5 text-sm text-muted-foreground">
                        {isFindingDetail
                          ? "Overview, source occurrences, and decision rationale"
                          : routeDetail.panelDetail}
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      type="button"
                      aria-label={
                        isFindingDetail
                          ? "Refresh finding detail"
                          : currentPath === "/waivers"
                            ? "Refresh waivers"
                            : "Refresh queue"
                      }
                      onClick={() => {
                        if (isFindingDetail) {
                          refreshFindingDetail()
                        } else if (currentPath === "/waivers") {
                          refreshWaivers()
                        }
                      }}
                    >
                      <Activity aria-hidden="true" size={18} />
                    </Button>
                  </div>
                )}

              {currentPath === "/projects" ? (
                <ProjectsWorkbench
                  createProjectError={createProjectError}
                  createProjectForm={createProjectForm}
                  deleteConfirmed={deleteConfirmed}
                  editProjectForm={editProjectForm}
                  editProjectId={editProjectId}
                  onCancelEditProject={() => setEditProjectId("")}
                  onCreateProject={createProject}
                  onCreateProjectDescriptionChange={(description) =>
                    setCreateProjectForm((form) => ({
                      ...form,
                      description,
                    }))
                  }
                  onCreateProjectNameChange={(name) =>
                    setCreateProjectForm((form) => ({
                      ...form,
                      name,
                    }))
                  }
                  onDeleteConfirmedChange={setDeleteConfirmed}
                  onDeleteProject={(project) => void deleteProject(project)}
                  onEditProjectDescriptionChange={(description) =>
                    setEditProjectForm((form) => ({
                      ...form,
                      description,
                    }))
                  }
                  onEditProjectNameChange={(name) =>
                    setEditProjectForm((form) => ({
                      ...form,
                      name,
                    }))
                  }
                  onRefreshProjects={() =>
                    void refreshProjects(selectedProjectId)
                  }
                  onSaveProject={saveProject}
                  onSelectProject={(projectId) => {
                    setSelectedProjectId(projectId)
                    setDeleteConfirmed(false)
                    setEditProjectId("")
                  }}
                  onStartEditProject={startEditProject}
                  projectActionError={projectActionError}
                  projectActionLoading={projectActionLoading}
                  projectActionMessage={projectActionMessage}
                  projectListLoading={projectListLoading}
                  projectSummary={projectSummary}
                  projectSummaryById={projectSummaryById}
                  projects={projects}
                  selectedProject={selectedProject}
                  selectedProjectId={selectedProjectId}
                />
              ) : currentPath === "/imports" ? (
                <ImportsWorkbench
                  importError={importError}
                  importLoading={importLoading}
                  importParseErrors={importParseErrors}
                  importRun={importRun}
                  importRunSummary={importRunSummary}
                  importWizard={importWizard}
                  onAssetContextFileChange={(file) =>
                    setImportWizard((state) => ({
                      ...state,
                      assetContextFile: file,
                    }))
                  }
                  onFileChange={(file) =>
                    setImportWizard((state) => ({ ...state, file }))
                  }
                  onInputTypeChange={(value) =>
                    setImportWizard((state) => ({
                      ...state,
                      inputType: value as ImportFormat,
                    }))
                  }
                  onProjectChange={setSelectedProjectId}
                  onRefreshRuns={() => void refreshProjectRuns(selectedRunId)}
                  onSelectRun={setSelectedRunId}
                  onSubmit={submitImport}
                  onVexFileChange={(file) =>
                    setImportWizard((state) => ({ ...state, vexFile: file }))
                  }
                  projectListLoading={projectListLoading}
                  projectRuns={projectRuns}
                  projects={projects}
                  providerStatus={providerStatus}
                  runDetailError={runDetailError}
                  runDetailLoading={runDetailLoading}
                  runsError={runsError}
                  runsLoading={runsLoading}
                  selectedProject={selectedProject}
                  selectedProjectId={selectedProjectId}
                  selectedRun={selectedRun}
                  selectedRunId={selectedRunId}
                  selectedRunSummary={selectedRunSummary}
                  supportedFormats={mvpImportFormats}
                />
              ) : isWaiversPage ? (
                <WaiversWorkbench
                  onCreateWaiver={createWaiver}
                  onExpireWaiver={(waiver) => void expireWaiver(waiver)}
                  onFieldChange={updateWaiverFormField}
                  onProjectChange={setSelectedProjectId}
                  onRefreshWaivers={refreshWaivers}
                  projectListLoading={projectListLoading}
                  projectSummary={projectSummary}
                  projects={projects}
                  selectedProject={selectedProject}
                  selectedProjectId={selectedProjectId}
                  waiverActionError={waiverActionError}
                  waiverActionLoading={waiverActionLoading}
                  waiverActionMessage={waiverActionMessage}
                  waiverDebtItems={waiverDebtItems}
                  waiverDebtSummary={waiverDebtSummary}
                  waiverForm={waiverForm}
                  waivers={waivers}
                  waiversError={waiversError || governanceError}
                  waiversLoading={waiversLoading || governanceLoading}
                />
              ) : isFindingDetail ? (
                <section
                  className="finding-decision-workflow"
                  aria-label="Finding priority decision"
                >
                  <div className="finding-detail-backbar">
                    <Button variant="outline" size="sm" asChild>
                      <Link to="/findings">
                        <ArrowLeft aria-hidden="true" size={16} />
                        <span>Back to Findings</span>
                      </Link>
                    </Button>
                  </div>

                  {findingDetailError ? (
                    <p
                      className="text-sm text-destructive rounded-md border border-destructive/20 bg-destructive/10 px-3 py-2"
                      role="alert"
                    >
                      {findingDetailError}
                    </p>
                  ) : null}
                  {findingExplanationWarning ? (
                    <p
                      className="text-sm text-destructive rounded-md border border-destructive/20 bg-destructive/10 px-3 py-2"
                      role="alert"
                    >
                      {findingExplanationWarning}
                    </p>
                  ) : null}
                  {findingDetailLoading ? (
                    <section
                      aria-label="Loading finding detail"
                      className="finding-decision-loading"
                      role="status"
                    >
                      <Skeleton className="h-8 w-40" />
                      <Skeleton className="h-36 w-full" />
                      <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
                        <Skeleton className="h-24 w-full" />
                        <Skeleton className="h-24 w-full" />
                        <Skeleton className="h-24 w-full" />
                        <Skeleton className="h-24 w-full" />
                      </div>
                    </section>
                  ) : null}

                  {!findingDetailLoading &&
                  !findingDetailError &&
                  findingDetail ? (
                    <>
                      {isDemoFindingDetail ? (
                        <section
                          aria-label="Demo Preview"
                          className="finding-demo-preview"
                        >
                          <Badge className="border-amber-200 bg-amber-50 text-amber-800">
                            Demo Preview
                          </Badge>
                          <span>
                            Sample evidence for the decision workflow. Not real
                            production data.
                          </span>
                        </section>
                      ) : null}

                      <section
                        className="finding-decision-hero"
                        aria-label="Finding decision hero"
                      >
                        <div className="finding-decision-hero-copy">
                          <Badge className="finding-decision-kicker">
                            Why this priority?
                          </Badge>
                          <h2>{findingDetail.cve_id}</h2>
                          <p>
                            {findingWhyText(findingDetail, findingExplanation)}
                          </p>
                          <div className="finding-decision-badges">
                            <PriorityBadge priority={findingDetail.priority} />
                            <FindingStatusBadge status={findingDetail.status} />
                            <KevBadge matched={findingDetail.in_kev} />
                          </div>
                        </div>
                        <ul
                          className="finding-decision-hero-metrics"
                          aria-label="Risk indicators"
                        >
                          <li className="finding-hero-metric-primary">
                            <span>Risk Score</span>
                            <strong>
                              {formatNullableNumber(findingDetail.risk_score)}
                            </strong>
                            <small>Operational remediation priority</small>
                          </li>
                          <li>
                            <span>EPSS</span>
                            <EpssBadge value={findingDetail.epss} />
                            <small>Exploit probability signal</small>
                          </li>
                          <li>
                            <span>CVSS</span>
                            <CvssBadge value={findingDetail.cvss_base_score} />
                            <small>Impact severity signal</small>
                          </li>
                          <li className="finding-hero-metric-decision">
                            <span>Decision</span>
                            <RiskScore value={findingDetail.risk_score} />
                            <small>
                              {findingSlaLabel(findingDetail.priority)} SLA
                            </small>
                          </li>
                        </ul>
                      </section>

                      <section
                        className="finding-decision-fact-grid"
                        aria-label="Finding scope"
                      >
                        <VpwSurface>
                          <VpwSurfaceHeader>
                            <VpwSurfaceDescription>
                              Component
                            </VpwSurfaceDescription>
                            <VpwSurfaceTitle
                              title={findingComponentDetailLabel(findingDetail)}
                            >
                              {findingComponentDetailLabel(findingDetail)}
                            </VpwSurfaceTitle>
                          </VpwSurfaceHeader>
                          <VpwSurfaceBody>
                            <p
                              title={optionalText(findingDetail.component_purl)}
                            >
                              {optionalText(findingDetail.component_purl)}
                            </p>
                          </VpwSurfaceBody>
                        </VpwSurface>
                        <VpwSurface>
                          <VpwSurfaceHeader>
                            <VpwSurfaceDescription>
                              Asset / Service
                            </VpwSurfaceDescription>
                            <VpwSurfaceTitle
                              title={findingAssetServiceDetailLabel(
                                findingDetail,
                              )}
                            >
                              {findingAssetServiceDetailLabel(findingDetail)}
                            </VpwSurfaceTitle>
                          </VpwSurfaceHeader>
                          <VpwSurfaceBody>
                            <p>{labelize(findingDetail.exposure)}</p>
                          </VpwSurfaceBody>
                        </VpwSurface>
                        <VpwSurface>
                          <VpwSurfaceHeader>
                            <VpwSurfaceDescription>Owner</VpwSurfaceDescription>
                            <VpwSurfaceTitle>
                              {findingOwnerDetailLabel(
                                findingDetail,
                                detailOccurrences,
                              )}
                            </VpwSurfaceTitle>
                          </VpwSurfaceHeader>
                          <VpwSurfaceBody>
                            <p>{labelize(findingDetail.asset_environment)}</p>
                          </VpwSurfaceBody>
                        </VpwSurface>
                        <VpwSurface className="finding-recommendation-card">
                          <VpwSurfaceHeader>
                            <VpwSurfaceDescription>
                              Primary recommendation
                            </VpwSurfaceDescription>
                            <VpwSurfaceTitle>
                              {findingRecommendedAction(
                                findingDetail,
                                findingExplanation,
                              )}
                            </VpwSurfaceTitle>
                          </VpwSurfaceHeader>
                        </VpwSurface>
                      </section>

                      <section
                        className="finding-decision-main-grid"
                        aria-label="Risk to decision"
                      >
                        <VpwSurface className="finding-decision-card finding-analysis-card">
                          <VpwSurfaceHeader>
                            <div className="finding-card-heading">
                              <div>
                                <VpwSurfaceDescription>
                                  Risk to Decision
                                </VpwSurfaceDescription>
                                <VpwSurfaceTitle>
                                  Why this priority?
                                </VpwSurfaceTitle>
                              </div>
                              <Badge variant="outline">
                                Score{" "}
                                {formatNullableNumber(findingDetail.risk_score)}
                              </Badge>
                            </div>
                          </VpwSurfaceHeader>
                          <VpwSurfaceBody>
                            <p className="finding-decision-lead">
                              {findingWhyText(
                                findingDetail,
                                findingExplanation,
                              )}
                            </p>
                            <ol
                              aria-label="Risk to decision chain"
                              className="finding-decision-chain"
                            >
                              <li>Finding</li>
                              <li>Priority</li>
                              <li>Evidence</li>
                              <li>Decision</li>
                            </ol>
                            <dl className="finding-decision-reasons">
                              {detailDecisionReasons.map((reason) => (
                                <div
                                  data-tone={reason.tone}
                                  key={`${reason.label}:${reason.detail}`}
                                >
                                  <dt>{reason.label}</dt>
                                  <dd>{reason.detail}</dd>
                                </div>
                              ))}
                            </dl>
                            {detailReasonRows.length > 0 ? (
                              <div className="finding-provider-reasons">
                                <span>Provider explanation</span>
                                <dl>
                                  {detailReasonRows.map((reason) => (
                                    <div
                                      key={`${reason.label}:${reason.detail}`}
                                    >
                                      <dt>{labelize(reason.label)}</dt>
                                      <dd>{reason.detail}</dd>
                                    </div>
                                  ))}
                                </dl>
                              </div>
                            ) : null}
                          </VpwSurfaceBody>
                        </VpwSurface>

                        <VpwSurface className="finding-decision-card finding-action-card">
                          <VpwSurfaceHeader>
                            <VpwSurfaceDescription>
                              Remediation
                            </VpwSurfaceDescription>
                            <VpwSurfaceTitle>Decision plan</VpwSurfaceTitle>
                          </VpwSurfaceHeader>
                          <VpwSurfaceBody>
                            <dl className="finding-decision-definition-list">
                              <div>
                                <dt>Recommended action</dt>
                                <dd>
                                  {findingRecommendedAction(
                                    findingDetail,
                                    findingExplanation,
                                  )}
                                </dd>
                              </div>
                              <div>
                                <dt>SLA</dt>
                                <dd>
                                  {findingSlaLabel(findingDetail.priority)}
                                </dd>
                              </div>
                              <div>
                                <dt>Owner</dt>
                                <dd>
                                  {findingOwnerDetailLabel(
                                    findingDetail,
                                    detailOccurrences,
                                  )}
                                </dd>
                              </div>
                              <div>
                                <dt>Next step</dt>
                                <dd>{findingNextStepLabel(findingDetail)}</dd>
                              </div>
                              <div>
                                <dt>Risk acceptance option</dt>
                                <dd>
                                  {detailWaiverEvidence
                                    ? `${optionalText(detailWaiverEvidence.status)} — ${optionalText(detailWaiverEvidence.reason)}`
                                    : "Available only with owner, expiry, approval reference, and compensating evidence."}
                                </dd>
                              </div>
                            </dl>
                            <div className="finding-decision-actions">
                              <Button
                                onClick={() =>
                                  setFindingDetailReloadKey(
                                    (value) => value + 1,
                                  )
                                }
                                size="sm"
                                type="button"
                                variant="outline"
                              >
                                Refresh evidence
                              </Button>
                            </div>
                          </VpwSurfaceBody>
                        </VpwSurface>
                      </section>

                      <Tabs
                        className="finding-detail-tabs-shell"
                        value={findingDetailTab}
                        onValueChange={(v) =>
                          setFindingDetailTab(v as FindingDetailTab)
                        }
                      >
                        <div className="finding-tabs-toolbar">
                          <div className="finding-tabs-heading">
                            <span>Decision evidence</span>
                            <strong>
                              Evidence, TTP context, and lifecycle
                            </strong>
                            <p>
                              Provider-backed facts used to explain and defend
                              the priority decision.
                            </p>
                          </div>
                          <TabsList className="finding-detail-tabs-list">
                            <TabsTrigger value="evidence">Evidence</TabsTrigger>
                            <TabsTrigger value="ttp">TTP Context</TabsTrigger>
                            <TabsTrigger value="history">History</TabsTrigger>
                          </TabsList>
                        </div>

                        <TabsContent
                          className="finding-detail-tab-panel"
                          value="evidence"
                        >
                          <section
                            className="finding-evidence-tab-layout"
                            aria-label="Evidence workspace"
                          >
                            <section
                              className="finding-evidence-grid"
                              aria-label="Evidence summary"
                            >
                              {detailEvidenceRows.map((row, index) => (
                                <VpwSurface
                                  className={cn(
                                    "finding-evidence-summary-card",
                                    index === 0
                                      ? "finding-evidence-summary-card-primary"
                                      : undefined,
                                  )}
                                  key={row.label}
                                >
                                  <VpwSurfaceHeader>
                                    <VpwSurfaceDescription>
                                      {row.label}
                                    </VpwSurfaceDescription>
                                    <VpwSurfaceTitle>
                                      {row.value}
                                    </VpwSurfaceTitle>
                                  </VpwSurfaceHeader>
                                  <VpwSurfaceBody>
                                    <p>{row.detail}</p>
                                  </VpwSurfaceBody>
                                </VpwSurface>
                              ))}
                            </section>

                            <section
                              className="finding-evidence-detail-grid"
                              aria-label="Evidence detail"
                            >
                              <VpwSurface
                                aria-label="Scanner occurrences"
                                className="finding-tab-card finding-occurrences-card"
                              >
                                <VpwSurfaceHeader>
                                  <div className="finding-card-heading">
                                    <div>
                                      <VpwSurfaceDescription>
                                        Scanner evidence
                                      </VpwSurfaceDescription>
                                      <VpwSurfaceTitle>
                                        Occurrences
                                      </VpwSurfaceTitle>
                                    </div>
                                    <Badge variant="outline">
                                      {detailOccurrences.length} source row(s)
                                    </Badge>
                                  </div>
                                </VpwSurfaceHeader>
                                <VpwSurfaceBody>
                                  {detailOccurrences.length > 0 ? (
                                    <div className="finding-detail-table-wrap">
                                      <Table aria-label="Occurrences table">
                                        <TableHeader>
                                          <TableRow>
                                            <TableHead>Source</TableHead>
                                            <TableHead>Component</TableHead>
                                            <TableHead>Asset / Owner</TableHead>
                                            <TableHead>Evidence</TableHead>
                                            <TableHead>Fix / VEX</TableHead>
                                          </TableRow>
                                        </TableHeader>
                                        <TableBody>
                                          {detailOccurrences.map(
                                            (occurrence, index) => {
                                              const fixVersions =
                                                Array.isArray(
                                                  occurrence.fix_versions,
                                                ) &&
                                                occurrence.fix_versions.length >
                                                  0
                                                  ? occurrence.fix_versions.join(
                                                      ", ",
                                                    )
                                                  : stringValue(
                                                      occurrence.fix_version,
                                                    )
                                              return (
                                                <TableRow
                                                  key={
                                                    stringValue(
                                                      occurrence.id,
                                                    ) ??
                                                    `occurrence-${index + 1}`
                                                  }
                                                >
                                                  <TableCell>
                                                    <span className="font-medium">
                                                      {optionalText(
                                                        stringValue(
                                                          occurrence.source_format,
                                                        ) ??
                                                          stringValue(
                                                            occurrence.source,
                                                          ),
                                                      )}
                                                    </span>
                                                    <small>
                                                      {optionalText(
                                                        stringValue(
                                                          occurrence.source_record_id,
                                                        ) ??
                                                          stringValue(
                                                            occurrence.raw_reference,
                                                          ),
                                                      )}
                                                    </small>
                                                  </TableCell>
                                                  <TableCell>
                                                    <span className="font-medium">
                                                      {joinedValues([
                                                        stringValue(
                                                          occurrence.component_name,
                                                        ),
                                                        stringValue(
                                                          occurrence.component_version,
                                                        ),
                                                      ])}
                                                    </span>
                                                    <small>
                                                      {optionalText(
                                                        stringValue(
                                                          occurrence.purl,
                                                        ),
                                                      )}
                                                    </small>
                                                  </TableCell>
                                                  <TableCell>
                                                    <span className="font-medium">
                                                      {optionalText(
                                                        stringValue(
                                                          occurrence.asset_ref,
                                                        ) ??
                                                          stringValue(
                                                            occurrence.target_ref,
                                                          ),
                                                      )}
                                                    </span>
                                                    <small>
                                                      {joinedValues([
                                                        stringValue(
                                                          occurrence.asset_owner,
                                                        ),
                                                        stringValue(
                                                          occurrence.asset_business_service,
                                                        ),
                                                        labelize(
                                                          stringValue(
                                                            occurrence.asset_exposure,
                                                          ),
                                                        ),
                                                      ])}
                                                    </small>
                                                  </TableCell>
                                                  <TableCell>
                                                    <span className="font-medium">
                                                      {optionalText(
                                                        stringValue(
                                                          occurrence.scanner,
                                                        ),
                                                      )}
                                                    </span>
                                                    <small>
                                                      {optionalText(
                                                        stringValue(
                                                          occurrence.raw_severity,
                                                        ),
                                                      )}
                                                    </small>
                                                  </TableCell>
                                                  <TableCell>
                                                    <span className="font-medium">
                                                      {optionalText(
                                                        fixVersions,
                                                      )}
                                                    </span>
                                                    <small>
                                                      {optionalText(
                                                        stringValue(
                                                          occurrence.vex_status,
                                                        )
                                                          ? labelize(
                                                              stringValue(
                                                                occurrence.vex_status,
                                                              ),
                                                            )
                                                          : stringValue(
                                                              occurrence.vex_justification,
                                                            ),
                                                      )}
                                                    </small>
                                                  </TableCell>
                                                </TableRow>
                                              )
                                            },
                                          )}
                                        </TableBody>
                                      </Table>
                                    </div>
                                  ) : (
                                    <p className="text-sm text-muted-foreground">
                                      No source occurrences have been recorded
                                      for this finding.
                                    </p>
                                  )}
                                </VpwSurfaceBody>
                              </VpwSurface>

                              <VpwSurface
                                aria-label="Data quality notes"
                                className="finding-tab-card finding-data-quality-card"
                              >
                                <VpwSurfaceHeader>
                                  <VpwSurfaceDescription>
                                    Provider data
                                  </VpwSurfaceDescription>
                                  <VpwSurfaceTitle>
                                    Data quality notes
                                  </VpwSurfaceTitle>
                                </VpwSurfaceHeader>
                                <VpwSurfaceBody>
                                  {detailDataQualityRows.length > 0 ? (
                                    <ul className="finding-data-quality-list">
                                      {detailDataQualityRows.map((flag) => (
                                        <li key={flag.key}>
                                          <strong>{labelize(flag.code)}</strong>
                                          <span>
                                            {flag.source} /{" "}
                                            {labelize(flag.severity)}
                                          </span>
                                          <p>{flag.message}</p>
                                        </li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <p className="text-sm text-muted-foreground">
                                      No data quality flags recorded.
                                    </p>
                                  )}
                                </VpwSurfaceBody>
                              </VpwSurface>
                            </section>
                          </section>
                        </TabsContent>

                        <TabsContent
                          className="finding-detail-tab-panel"
                          value="ttp"
                        >
                          <VpwSurface
                            aria-label="TTP Context"
                            className="finding-tab-card finding-ttp-card"
                          >
                            <VpwSurfaceHeader>
                              <div className="finding-card-heading">
                                <div>
                                  <VpwSurfaceDescription>
                                    ATT&amp;CK
                                  </VpwSurfaceDescription>
                                  <VpwSurfaceTitle>TTP Context</VpwSurfaceTitle>
                                </div>
                                <Badge variant="outline">
                                  {detailAttackSource
                                    ?.toLowerCase()
                                    .includes("demo")
                                    ? "Curated demo mapping"
                                    : detailAttackContext?.mapped
                                      ? "Mapped context"
                                      : "No approved mapping"}
                                </Badge>
                              </div>
                            </VpwSurfaceHeader>
                            <VpwSurfaceBody>
                              {detailAttackEmpty ? (
                                <section
                                  aria-label="TTP context empty state"
                                  className="finding-empty-panel"
                                >
                                  <div className="finding-empty-panel-heading">
                                    <Badge variant="outline">
                                      Defensive context
                                    </Badge>
                                    <strong>
                                      No approved ATT&amp;CK mapping is stored
                                      for this finding.
                                    </strong>
                                  </div>
                                  <p>
                                    Workbench does not infer tactics or
                                    techniques for unmapped CVEs. Add a reviewed
                                    CTID or curated local mapping before using
                                    ATT&amp;CK context in queue decisions.
                                  </p>
                                </section>
                              ) : (
                                <>
                                  <section
                                    className="finding-ttp-context-hero finding-ttp-context-hero-simple"
                                    aria-label="Threat informed context"
                                  >
                                    <div className="finding-ttp-main-copy">
                                      <span>Threat informed context</span>
                                      <h3>{detailAttackTechniqueLabel}</h3>
                                      <p>
                                        This mapping explains why the finding is
                                        treated as an internet-facing Initial
                                        Access risk. It supports remediation
                                        priority and detection coverage review,
                                        but does not prove exploitation.
                                      </p>
                                    </div>
                                    <dl className="finding-ttp-main-facts">
                                      <div>
                                        <dt>Tactic</dt>
                                        <dd>{detailAttackTacticLabel}</dd>
                                      </div>
                                      <div>
                                        <dt>Confidence</dt>
                                        <dd>
                                          <Badge
                                            className={cn(
                                              detailAttackContext?.confidence ===
                                                "high"
                                                ? "bg-green-100 text-green-700 border-green-200"
                                                : detailAttackContext?.confidence ===
                                                    "low"
                                                  ? "bg-red-100 text-red-700 border-red-200"
                                                  : "bg-yellow-100 text-yellow-700 border-yellow-200",
                                            )}
                                          >
                                            {attackConfidenceLabel(
                                              detailAttackContext?.confidence,
                                            )}
                                          </Badge>
                                        </dd>
                                      </div>
                                      <div>
                                        <dt>Source</dt>
                                        <dd>
                                          {optionalText(detailAttackSource)}
                                        </dd>
                                      </div>
                                      <div>
                                        <dt>Coverage</dt>
                                        <dd>{detailAttackCoverageStatus}</dd>
                                      </div>
                                    </dl>
                                  </section>

                                  <ol
                                    className="finding-ttp-chain finding-ttp-chain-compact"
                                    aria-label="Attack chain and decision flow"
                                  >
                                    <li data-tone="signal">
                                      <span className="finding-ttp-chain-index">
                                        1
                                      </span>
                                      <div>
                                        <small>CVE signal</small>
                                        <strong>High priority signal</strong>
                                      </div>
                                    </li>
                                    <li data-tone="exposure">
                                      <span className="finding-ttp-chain-index">
                                        2
                                      </span>
                                      <div>
                                        <small>Internet-facing asset</small>
                                        <strong>Internet facing asset</strong>
                                      </div>
                                    </li>
                                    <li data-tone="technique">
                                      <span className="finding-ttp-chain-index">
                                        3
                                      </span>
                                      <div>
                                        <small>ATT&amp;CK technique</small>
                                        <strong>
                                          {detailAttackTechniqueId}
                                        </strong>
                                      </div>
                                    </li>
                                    <li data-tone="coverage">
                                      <span className="finding-ttp-chain-index">
                                        4
                                      </span>
                                      <div>
                                        <small>Detection gap</small>
                                        <strong>
                                          {detailAttackCoverageStatus}
                                        </strong>
                                      </div>
                                    </li>
                                    <li data-tone="decision">
                                      <span className="finding-ttp-chain-index">
                                        5
                                      </span>
                                      <div>
                                        <small>Remediation priority</small>
                                        <strong>Emergency remediation</strong>
                                      </div>
                                    </li>
                                  </ol>

                                  <section
                                    className="finding-ttp-decision-grid finding-ttp-decision-grid-simple"
                                    aria-label="Threat informed decision context"
                                  >
                                    <article className="finding-ttp-narrative-card">
                                      <span>Why this matters</span>
                                      <strong>Decision support</strong>
                                      <ul className="finding-ttp-meaning-list">
                                        <li>
                                          Frames the CVE as an Initial Access
                                          risk.
                                        </li>
                                        <li>
                                          Explains why internet exposure raises
                                          urgency.
                                        </li>
                                        <li>
                                          Connects remediation priority with
                                          detection review.
                                        </li>
                                        <li>
                                          Keeps the boundary clear: no proof of
                                          exploitation.
                                        </li>
                                      </ul>
                                    </article>
                                    <article className="finding-ttp-narrative-card finding-ttp-actions-card">
                                      <span>Recommended defensive actions</span>
                                      <strong>
                                        Close exposure and validate coverage
                                      </strong>
                                      <ul className="finding-ttp-checklist">
                                        {(detailAttackActionItems.length > 0
                                          ? detailAttackActionItems
                                          : [
                                              "Patch or mitigate the vulnerable service.",
                                              "Restrict exposure while remediation is in progress.",
                                              "Validate web, proxy, WAF, EDR and application telemetry.",
                                              "Document detection coverage and residual risk.",
                                            ]
                                        ).map((item) => (
                                          <li key={item}>{item}</li>
                                        ))}
                                      </ul>
                                    </article>
                                  </section>

                                  <details className="finding-ttp-technical-evidence finding-ttp-technical-details">
                                    <summary className="finding-ttp-technical-heading">
                                      <div>
                                        <span>Secondary evidence</span>
                                        <strong>
                                          Technical mapping details
                                        </strong>
                                      </div>
                                      <Badge variant="outline">
                                        Source, confidence, rationale
                                      </Badge>
                                    </summary>

                                    <div className="finding-ttp-technical-body">
                                      <p>
                                        {optionalText(detailAttackRationale)}
                                      </p>
                                      <div className="finding-detail-table-wrap">
                                        <Table aria-label="TTP Context techniques">
                                          <TableHeader>
                                            <TableRow>
                                              <TableHead>Technique</TableHead>
                                              <TableHead>Tactic</TableHead>
                                              <TableHead>Confidence</TableHead>
                                              <TableHead>Source</TableHead>
                                              <TableHead>Rationale</TableHead>
                                              <TableHead>
                                                Defensive actions
                                              </TableHead>
                                            </TableRow>
                                          </TableHeader>
                                          <TableBody>
                                            {detailAttackTechniques.map(
                                              (technique) => {
                                                const actionItems =
                                                  defensiveActionItems(
                                                    technique.defensive_note,
                                                  )
                                                return (
                                                  <TableRow
                                                    key={technique.technique_id}
                                                  >
                                                    <TableCell>
                                                      <span className="font-medium">
                                                        {technique.technique_id}
                                                      </span>
                                                      <small>
                                                        {optionalText(
                                                          technique.name,
                                                        )}
                                                      </small>
                                                    </TableCell>
                                                    <TableCell>
                                                      {attackTacticsLabel(
                                                        technique.tactics,
                                                      )}
                                                    </TableCell>
                                                    <TableCell>
                                                      <Badge
                                                        className={cn(
                                                          technique.confidence ===
                                                            "high"
                                                            ? "bg-green-100 text-green-700 border-green-200"
                                                            : technique.confidence ===
                                                                "low"
                                                              ? "bg-red-100 text-red-700 border-red-200"
                                                              : "bg-yellow-100 text-yellow-700 border-yellow-200",
                                                        )}
                                                      >
                                                        {attackConfidenceLabel(
                                                          technique.confidence,
                                                        )}
                                                      </Badge>
                                                    </TableCell>
                                                    <TableCell>
                                                      {optionalText(
                                                        attackSourceLabel(
                                                          technique.source,
                                                          detailAttackContext,
                                                        ),
                                                      )}
                                                    </TableCell>
                                                    <TableCell>
                                                      {optionalText(
                                                        technique.rationale,
                                                      )}
                                                    </TableCell>
                                                    <TableCell>
                                                      {actionItems.length >
                                                      1 ? (
                                                        <ul className="finding-ttp-actions-list">
                                                          {actionItems.map(
                                                            (item) => (
                                                              <li key={item}>
                                                                {item}
                                                              </li>
                                                            ),
                                                          )}
                                                        </ul>
                                                      ) : (
                                                        optionalText(
                                                          technique.defensive_note,
                                                        )
                                                      )}
                                                    </TableCell>
                                                  </TableRow>
                                                )
                                              },
                                            )}
                                          </TableBody>
                                        </Table>
                                      </div>
                                    </div>
                                  </details>
                                </>
                              )}
                              {detailAttackEmpty ? (
                                <section
                                  className="finding-detection-note"
                                  aria-label="Detection coverage"
                                >
                                  <span>Detection coverage</span>
                                  <p>
                                    {optionalText(
                                      detailAttackContext?.defensive_note ??
                                        "Coverage controls are not connected to this finding yet. Record detection and mitigation evidence when available.",
                                    )}
                                  </p>
                                </section>
                              ) : null}
                              <p className="finding-defensive-note">
                                Defensive context only. No exploit steps,
                                payloads, PoC guidance, active probing, or
                                offensive procedure instructions.
                              </p>
                            </VpwSurfaceBody>
                          </VpwSurface>
                        </TabsContent>

                        <TabsContent
                          className="finding-detail-tab-panel"
                          value="history"
                        >
                          <section
                            className="finding-history-timeline"
                            aria-label="Finding history"
                          >
                            {detailHistoryRows.map((row, index) => (
                              <VpwSurface
                                className="finding-tab-card finding-history-event"
                                key={row.label}
                              >
                                <VpwSurfaceHeader>
                                  <span className="finding-history-step">
                                    {index + 1}
                                  </span>
                                  <div>
                                    <VpwSurfaceDescription>
                                      {row.label}
                                    </VpwSurfaceDescription>
                                    <VpwSurfaceTitle>
                                      {row.value}
                                    </VpwSurfaceTitle>
                                  </div>
                                </VpwSurfaceHeader>
                                <VpwSurfaceBody>
                                  <p>{row.detail}</p>
                                </VpwSurfaceBody>
                              </VpwSurface>
                            ))}
                          </section>
                          {detailWaiverEvidence ? (
                            <VpwSurface
                              aria-label="Accepted risk"
                              className="finding-tab-card finding-accepted-risk-card"
                            >
                              <VpwSurfaceHeader>
                                <VpwSurfaceDescription>
                                  Risk acceptance
                                </VpwSurfaceDescription>
                                <VpwSurfaceTitle>Accepted risk</VpwSurfaceTitle>
                              </VpwSurfaceHeader>
                              <VpwSurfaceBody>
                                <dl className="finding-decision-definition-list compact">
                                  <div>
                                    <dt>Owner</dt>
                                    <dd>
                                      {optionalText(detailWaiverEvidence.owner)}
                                    </dd>
                                  </div>
                                  <div>
                                    <dt>Reason</dt>
                                    <dd>
                                      {optionalText(
                                        detailWaiverEvidence.reason,
                                      )}
                                    </dd>
                                  </div>
                                  <div>
                                    <dt>Expires</dt>
                                    <dd>
                                      {optionalText(
                                        detailWaiverEvidence.expiresOn,
                                      )}
                                    </dd>
                                  </div>
                                  <div>
                                    <dt>Review</dt>
                                    <dd>
                                      {optionalText(
                                        detailWaiverEvidence.reviewOn,
                                      )}
                                    </dd>
                                  </div>
                                  <div>
                                    <dt>Scope</dt>
                                    <dd>
                                      {optionalText(
                                        detailWaiverEvidence.matchedScope ??
                                          detailWaiverEvidence.scope,
                                      )}
                                    </dd>
                                  </div>
                                  <div>
                                    <dt>Approval</dt>
                                    <dd>
                                      {optionalText(
                                        detailWaiverEvidence.approvalRef,
                                      )}
                                    </dd>
                                  </div>
                                </dl>
                              </VpwSurfaceBody>
                            </VpwSurface>
                          ) : null}
                        </TabsContent>
                      </Tabs>
                    </>
                  ) : null}
                </section>
              ) : currentPath === "/providers" ? (
                <ProvidersRouteContainer
                  onRefreshProviderStatus={refreshProviderStatus}
                  providerStatus={providerStatus}
                  providerStatusError={providerStatusError}
                  providerStatusLoading={providerStatusLoading}
                />
              ) : currentPath === "/settings" ? (
                <SettingsRouteContainer
                  apiTokenActionLoading={apiTokenActionLoading}
                  apiTokenError={apiTokenError}
                  apiTokenMessage={apiTokenMessage}
                  apiTokenName={apiTokenName}
                  apiTokenScopeOptions={apiTokenScopeOptions}
                  apiTokenScopes={apiTokenScopes}
                  apiTokens={apiTokens}
                  apiTokensLoading={apiTokensLoading}
                  createdApiToken={createdApiToken}
                  currentUser={currentUser}
                  onApiTokenNameChange={setApiTokenName}
                  onCreateApiToken={createApiToken}
                  onRevokeApiToken={revokeApiToken}
                  onToggleApiTokenScope={toggleApiTokenScope}
                  providerStatus={providerStatus}
                  providerStatusError={providerStatusError}
                  providerStatusLoading={providerStatusLoading}
                  status={status}
                  statusError={statusError}
                />
              ) : currentPath === "/reports" ? (
                <EvidenceCenter
                  activeReportFormat={activeReportFormat}
                  onCreateReport={createReport}
                  onDownloadReport={downloadReport}
                  onRunIdChange={setSelectedRunId}
                  onVerifyReport={verifyEvidenceReport}
                  projectRuns={projectRuns}
                  projectSummary={projectSummary}
                  providerStatus={providerStatus}
                  reportActionError={reportActionError}
                  reportActionMessage={reportActionMessage}
                  reportActionsEnabled={reportActionsEnabled}
                  reports={reports}
                  reportsError={reportsError}
                  reportsLoading={reportsLoading}
                  runDetailError={runDetailError}
                  runsError={runsError}
                  runsLoading={runsLoading}
                  selectedProject={selectedProject}
                  selectedReportRun={selectedReportRun}
                  selectedRunId={selectedRunId}
                  selectedRunSummary={selectedRunSummary}
                />
              ) : (
                <div className="dashboard-panel-body">
                  {dashboardError ? (
                    <ErrorState message={dashboardError} />
                  ) : null}

                  {dashboardLoading ? (
                    <LoadingSkeleton label="Loading dashboard summary" />
                  ) : null}

                  {!dashboardLoading &&
                  !dashboardError &&
                  projects.length === 0 ? (
                    <EmptyState
                      action={
                        <div className="flex gap-2">
                          <Button asChild>
                            <Link to="/projects">Projects</Link>
                          </Button>
                          <Button variant="outline" asChild>
                            <Link to="/imports">Imports</Link>
                          </Button>
                        </div>
                      }
                      ariaLabel="Dashboard empty state"
                      detail="Create a project or import a CVE list to populate the dashboard."
                      title="No projects yet"
                    />
                  ) : null}

                  {!dashboardLoading &&
                  !dashboardError &&
                  selectedProject &&
                  projectSummary !== null &&
                  (projectSummary.finding_count ?? 0) === 0 ? (
                    <EmptyState
                      action={
                        <div className="flex gap-2">
                          <Button asChild>
                            <Link to="/imports">Imports</Link>
                          </Button>
                          <Button variant="outline" asChild>
                            <Link to="/projects">Projects</Link>
                          </Button>
                        </div>
                      }
                      ariaLabel="No findings empty state"
                      detail="Import scanner, SBOM, or CVE-list data to create findings."
                      title={`No findings in ${selectedProject.name}`}
                    />
                  ) : null}

                  {!dashboardLoading &&
                  !dashboardError &&
                  projects.length > 0 ? (
                    <div className="dashboard-cockpit-grid">
                      <div className="dashboard-main-stack">
                        {selectedProject &&
                        projectSummary !== null &&
                        (projectSummary.finding_count ?? 0) > 0 ? (
                          <TopRemediationQueue
                            error={dashboardFindingsError}
                            findings={dashboardFindings}
                            loading={dashboardFindingsLoading}
                            projectName={selectedProject.name}
                          />
                        ) : null}

                        <section
                          className="dashboard-chart-grid"
                          aria-label="Dashboard chart previews"
                        >
                          <FindingsByPriorityChart items={priorityChartItems} />
                          <TopServicesByRiskChart
                            items={topServiceChartItems}
                            source={topServiceSource}
                          />
                          <RiskTrendChart items={runActivityItems} />
                        </section>

                        {projectSummary !== null &&
                        (projectSummary.finding_count ?? 0) > 0 ? (
                          <dl
                            className="summary-list"
                            aria-label="Project decision summary"
                          >
                            {summaryRows.map((row) => (
                              <div key={row.label}>
                                <dt>{row.label}</dt>
                                <dd>
                                  <strong>{row.value}</strong>
                                  <span>{row.detail}</span>
                                </dd>
                              </div>
                            ))}
                          </dl>
                        ) : null}

                        {governanceError ? (
                          <ErrorState message={governanceError} />
                        ) : null}

                        {governanceLoading ? (
                          <LoadingSkeleton label="Loading governance rollups" />
                        ) : null}

                        {!governanceLoading &&
                        !governanceError &&
                        selectedProject &&
                        projectGovernanceRollups ? (
                          <section
                            className="governance-summary-widget"
                            aria-label="Top Services by Risk"
                          >
                            <div className="flex items-center justify-between mb-4">
                              <h3 className="font-semibold">
                                {topServiceSource === "assets"
                                  ? "Top Assets by Risk"
                                  : "Top Services by Risk"}
                              </h3>
                              <span className="text-sm text-muted-foreground">
                                {topServiceSource === "assets"
                                  ? "Assets and waiver debt concentration"
                                  : "Owner, service, and waiver debt concentration"}
                              </span>
                            </div>
                            {topServiceChartRows.length === 0 ? (
                              <p className="attack-summary-empty">
                                No service or asset rollups are available for
                                this project. Import findings with service or
                                asset context and rerun analysis to enable risk
                                ranking.
                              </p>
                            ) : (
                              <ul className="governance-service-list">
                                {topServiceChartRows.map((service) => (
                                  <li key={service.label}>
                                    <div>
                                      <strong>{service.label}</strong>
                                      <span>
                                        {service.finding_count ?? 0} finding
                                        {service.finding_count === 1 ? "" : "s"}
                                      </span>
                                    </div>
                                    <small>
                                      Highest{" "}
                                      {service.highest_priority ?? "Unreviewed"}{" "}
                                      / Critical {service.critical_count ?? 0} /
                                      High {service.high_count ?? 0} / Score{" "}
                                      {formatRollupScore(
                                        service.risk_score_total,
                                      )}{" "}
                                      / Waiver debt{" "}
                                      {serviceWaiverDebtCount(service)}
                                    </small>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </section>
                        ) : null}
                      </div>

                      <aside
                        className="dashboard-side-stack"
                        aria-label="Dashboard evidence panels"
                      >
                        <ProviderFreshnessPanel
                          providerStatus={providerStatus}
                          statusError={providerStatusError || statusError}
                        />

                        <section
                          className="dashboard-readiness-card"
                          aria-label="Evidence Readiness"
                        >
                          <div className="dashboard-panel-heading">
                            <div>
                              <span>Report Inputs</span>
                              <h3>Evidence Readiness</h3>
                              <p>Latest run context for report generation.</p>
                            </div>
                            <Button variant="outline" size="sm" asChild>
                              <Link to="/reports">Reports</Link>
                            </Button>
                          </div>

                          {runsError ? (
                            <ErrorState message={runsError} />
                          ) : null}

                          <dl className="dashboard-readiness-facts">
                            <div>
                              <dt>Latest run</dt>
                              <dd>
                                {runsLoading
                                  ? "Loading"
                                  : latestProjectRun
                                    ? runStatusLabel(latestProjectRun.status)
                                    : "No runs"}
                              </dd>
                            </div>
                            <div>
                              <dt>Run started</dt>
                              <dd>
                                {latestProjectRun?.started_at
                                  ? formatDateTime(latestProjectRun.started_at)
                                  : "N.A."}
                              </dd>
                            </div>
                            <div>
                              <dt>Findings</dt>
                              <dd>{projectSummary?.finding_count ?? 0}</dd>
                            </div>
                            <div>
                              <dt>Reports</dt>
                              <dd>
                                {latestProjectRun
                                  ? "Ready for generation"
                                  : "Import data first"}
                              </dd>
                            </div>
                          </dl>
                        </section>
                      </aside>
                    </div>
                  ) : null}
                </div>
              )}
            </div>

            {!isFindingsList &&
              !isFindingDetail &&
              currentPath !== "/reports" &&
              currentPath !== "/settings" &&
              currentPath !== "/providers" && (
                <div className="side-panel">
                  <section aria-label="Provider Status">
                    <div className="panel-header compact inline-header">
                      <div>
                        <h2>Provider Status</h2>
                        <span>{providerSnapshotSummary(providerStatus)}</span>
                      </div>
                      <Database aria-hidden="true" size={18} />
                    </div>

                    <div
                      className={`provider-state ${
                        providerStatus?.status === "ok" ? "ok" : "degraded"
                      }`}
                    >
                      <span>{providerStatus?.status ?? "loading"}</span>
                      <strong>
                        {providerStatus?.snapshot_mode ?? "missing"}
                      </strong>
                    </div>

                    <dl className="provider-facts">
                      <div>
                        <dt>Snapshot mode</dt>
                        <dd>{providerStatus?.snapshot_mode ?? "missing"}</dd>
                      </div>
                      <div>
                        <dt>Last sync</dt>
                        <dd>{providerStatus?.last_sync ?? "N.A."}</dd>
                      </div>
                      <div>
                        <dt>Cache age</dt>
                        <dd>
                          {formatCacheAge(providerStatus?.cache_age_seconds)}
                        </dd>
                      </div>
                      <div>
                        <dt>Last error</dt>
                        <dd>
                          {providerStatus?.last_error ??
                            (statusError || "None")}
                        </dd>
                      </div>
                    </dl>

                    <ul
                      className="provider-sources"
                      aria-label="Provider sources"
                    >
                      {(providerStatus?.sources ?? fallbackProviderSources).map(
                        (source) => (
                          <li className="provider-source" key={source.name}>
                            <div>
                              <strong>{source.name.toUpperCase()}</strong>
                              <span>{source.value ?? "N.A."}</span>
                            </div>
                            <Badge
                              className={
                                source.available
                                  ? "bg-green-100 text-green-700 border-green-200"
                                  : "bg-red-100 text-red-700 border-red-200"
                              }
                            >
                              {source.available ? "available" : "missing"}
                            </Badge>
                          </li>
                        ),
                      )}
                    </ul>

                    {(providerStatus?.warnings ?? []).map((warning) => (
                      <p className="provider-warning" key={warning}>
                        {warning}
                      </p>
                    ))}
                  </section>

                  <div className="panel-header compact">
                    <div>
                      <h2>Evidence Flow</h2>
                      <span>Latest workspace events</span>
                    </div>
                    <GitBranch aria-hidden="true" size={18} />
                  </div>
                  <ol className="timeline">
                    {timeline.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ol>
                  <section
                    className="attack-summary-widget"
                    aria-label="Top ATT&CK techniques dashboard widget"
                  >
                    <div className="panel-header compact inline-header">
                      <div>
                        <h2>Top ATT&CK Techniques</h2>
                        <span>
                          {projectAttackSummary
                            ? attackConfidenceSummary(projectAttackSummary)
                            : "Confidence distribution loading"}
                        </span>
                      </div>
                      <BarChart3 aria-hidden="true" size={18} />
                    </div>

                    {attackSummaryError ? (
                      <p
                        className="text-sm text-destructive rounded-md border border-destructive/20 bg-destructive/10 px-3 py-2"
                        role="alert"
                      >
                        {attackSummaryError}
                      </p>
                    ) : null}

                    {attackSummaryLoading ? (
                      <p
                        className="text-sm text-muted-foreground"
                        role="status"
                      >
                        Loading ATT&CK summary
                      </p>
                    ) : null}

                    {!attackSummaryLoading &&
                    !attackSummaryError &&
                    (!selectedProject || !projectAttackSummary) ? (
                      <p className="attack-summary-empty">
                        Select a project to review ATT&CK concentration.
                      </p>
                    ) : null}

                    {!attackSummaryLoading &&
                    !attackSummaryError &&
                    projectAttackSummary &&
                    attackTopTechniques.length === 0 ? (
                      <p className="attack-summary-empty">
                        No reviewed ATT&CK technique mappings are stored for
                        this project.
                      </p>
                    ) : null}

                    {!attackSummaryLoading &&
                    !attackSummaryError &&
                    projectAttackSummary &&
                    attackTopTechniques.length > 0 ? (
                      <>
                        <dl className="attack-summary-stats">
                          {attackRows.map((row) => (
                            <div key={row.label}>
                              <dt>{row.label}</dt>
                              <dd>
                                <strong>{row.value}</strong>
                                <span>{row.detail}</span>
                              </dd>
                            </div>
                          ))}
                        </dl>
                        <ul className="attack-technique-list">
                          {attackTopTechniques.map((technique) => (
                            <li key={technique.technique_id}>
                              <div>
                                <strong>{technique.technique_id}</strong>
                                <span>
                                  {technique.name ?? "Unnamed technique"}
                                </span>
                              </div>
                              <small>
                                {technique.finding_count} finding
                                {technique.finding_count === 1 ? "" : "s"} /{" "}
                                {attackTechniqueConfidenceLabel(technique)}
                              </small>
                            </li>
                          ))}
                        </ul>
                        <p className="attack-summary-note">
                          {projectAttackSummary.defensive_note}
                        </p>
                      </>
                    ) : null}
                  </section>
                </div>
              )}
          </section>
        )}
      </Suspense>
    </ProductAppShell>
  )
}

const fallbackProviderSources: ProviderSourceStatusPublic[] = [
  { name: "nvd", available: false, value: null },
  { name: "epss", available: false, value: null },
  { name: "kev", available: false, value: null },
]
