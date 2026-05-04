import { Link, useLocation, useNavigate } from "@tanstack/react-router"
import {
  Activity,
  AlertTriangle,
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
import { ProductAppShell, type WorkbenchPath } from "../components/app/AppShell"
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
  demoFindingDetailForId,
  demoFindingExplanationForDetail,
} from "../components/finding-detail/finding-detail-model"
import { useFindingsRouteState } from "../components/findings/useFindingsRouteState"
import {
  type DataQualityNoticeItem,
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from "../components/states"
import { Badge } from "../components/ui/badge"
import { Button } from "../components/ui/button"
import {
  type ApiTokenScope,
  apiTokenScopeOptions,
  canonicalApiTokenScopes,
  defaultApiTokenScopes,
  defaultImportWizardState,
  emptyProjectForm,
  type FindingDetailTab,
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
  formatCacheAge,
  formatProviderFreshness,
  providerDataQualityNotes,
  providerSnapshotSummary,
} from "../lib/provider-format"
import { runStatusLabel } from "../lib/risk-format"
import { formatLabel as labelize } from "../lib/ui-copy"
import {
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
const FindingDetailRoute = lazy(() =>
  import("../components/finding-detail/FindingDetailRoute").then((module) => ({
    default: module.FindingDetailRoute,
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

function numericFilterValue(value: string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return undefined
  }
  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : undefined
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
  const {
    activeFindingFilters,
    clearFindingFilters,
    findingDirection,
    findingFilters,
    findingOffset,
    findingPageSize,
    findingSort,
    nextFindingPage,
    previousFindingPage,
    resetFindingOffset,
    updateFindingDirection,
    updateFindingFilter,
    updateFindingPageSize,
    updateFindingSort,
  } = useFindingsRouteState({
    hasAssetFilter: Boolean(findingAssetId),
    onClearAssetFilter: () => {
      void navigate({ to: "/findings" })
    },
  })
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
              onPageNext={nextFindingPage}
              onPagePrev={previousFindingPage}
              onPageSizeChange={updateFindingPageSize}
              onProjectChange={(id) => {
                resetFindingOffset()
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
                <FindingDetailRoute
                  error={findingDetailError}
                  explanation={findingExplanation}
                  explanationWarning={findingExplanationWarning}
                  finding={findingDetail}
                  loading={findingDetailLoading}
                  onRefresh={refreshFindingDetail}
                  onTabChange={setFindingDetailTab}
                  tab={findingDetailTab}
                />
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
