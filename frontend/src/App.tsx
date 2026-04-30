import { Link, useLocation, useNavigate } from "@tanstack/react-router"
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BarChart3,
  Database,
  Download,
  FileArchive,
  FileCheck2,
  FileInput,
  FileJson,
  FileText,
  FolderKanban,
  Gauge,
  GitBranch,
  History,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Settings,
  ShieldCheck,
  Table2,
} from "lucide-react"
import { type FormEvent, useEffect, useState } from "react"
import { clearAccessToken, getAccessToken } from "./auth"
import {
  type AnalysisRunPublic,
  type AnalysisRunSummaryPublic,
  ApiError,
  type AssetExposure,
  type FindingDetailPublic,
  type FindingExplanationPublic,
  type FindingOccurrencePublic,
  type FindingPriority,
  type FindingPublic,
  type FindingStatus,
  type FindingsReadProjectFindingsData,
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
  RunsService,
  type UserPublic,
  UsersService,
  type WaiverCreate,
  type WaiverPublic,
  WaiversService,
  WorkbenchService,
  type WorkbenchStatus,
} from "./client"

const workbenchNavigation = [
  { label: "Dashboard", icon: LayoutDashboard, to: "/" },
  { label: "Projects", icon: FolderKanban, to: "/projects" },
  { label: "Imports", icon: FileInput, to: "/imports" },
  { label: "Findings", icon: ListChecks, to: "/findings" },
  { label: "Waivers", icon: FileCheck2, to: "/waivers" },
  { label: "Assets", icon: ShieldCheck, to: "/assets" },
  { label: "Providers", icon: Database, to: "/providers" },
  { label: "Reports", icon: FileArchive, to: "/reports" },
  { label: "Settings", icon: Settings, to: "/settings" },
] as const

const routeDetails: Record<
  (typeof workbenchNavigation)[number]["to"],
  {
    eyebrow: string
    title: string
    panelTitle: string
    panelDetail: string
  }
> = {
  "/": {
    eyebrow: "VPW Template Migration",
    title: "Risk Operations",
    panelTitle: "Priority Queue",
    panelDetail: "Current project signal review",
  },
  "/projects": {
    eyebrow: "Workbench Projects",
    title: "Projects",
    panelTitle: "Project Coverage",
    panelDetail: "Visible workspaces and decision backlog",
  },
  "/imports": {
    eyebrow: "Workbench Imports",
    title: "Imports",
    panelTitle: "Import Queue",
    panelDetail: "Normalized scanner, SBOM, and CVE-list inputs",
  },
  "/findings": {
    eyebrow: "Workbench Findings",
    title: "Findings",
    panelTitle: "Finding Decisions",
    panelDetail: "Prioritized CVEs awaiting review",
  },
  "/waivers": {
    eyebrow: "Risk Acceptance",
    title: "Waivers",
    panelTitle: "Waiver Register",
    panelDetail: "Scoped accepted-risk decisions and lifecycle review",
  },
  "/assets": {
    eyebrow: "Workbench Assets",
    title: "Assets",
    panelTitle: "Asset Context",
    panelDetail: "Business and exposure context for ranking",
  },
  "/providers": {
    eyebrow: "Workbench Providers",
    title: "Providers",
    panelTitle: "Provider Signals",
    panelDetail: "NVD, EPSS, KEV, and local snapshot status",
  },
  "/reports": {
    eyebrow: "Workbench Reports",
    title: "Reports",
    panelTitle: "Evidence Outputs",
    panelDetail: "Report and evidence bundle readiness",
  },
  "/settings": {
    eyebrow: "Workbench Settings",
    title: "Settings",
    panelTitle: "User Settings",
    panelDetail: "Current authenticated user and workspace session",
  },
}

type WorkbenchPath = keyof typeof routeDetails

function normalizeWorkbenchPath(pathname: string): WorkbenchPath {
  const normalized =
    pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname
  if (normalized.startsWith("/findings/")) {
    return "/findings"
  }
  return normalized in routeDetails ? (normalized as WorkbenchPath) : "/"
}

function findingIdFromPath(pathname: string) {
  const normalized =
    pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname
  const match = normalized.match(/^\/findings\/([^/]+)$/)
  return match ? decodeURIComponent(match[1]) : null
}

function isActivePath(currentPath: WorkbenchPath, targetPath: WorkbenchPath) {
  return currentPath === targetPath
}

const currentUserLabel = (user: UserPublic | null) =>
  user?.email ?? "Local workspace"

const settingsSummary = (user: UserPublic | null) => [
  {
    label: "Signed-in user",
    value: currentUserLabel(user),
  },
  {
    label: "Session",
    value: user ? "Authenticated" : "Loading",
  },
]

type ProjectFormState = {
  name: string
  description: string
}

const emptyProjectForm: ProjectFormState = {
  name: "",
  description: "",
}

const mvpImportFormats = [
  {
    label: "CVE list",
    value: "cve-list",
    accept: ".txt,.csv,text/plain,text/csv",
    detail: "Plain text or CSV with one CVE identifier per line.",
  },
  {
    label: "Generic occurrence CSV",
    value: "generic-occurrence-csv",
    accept: ".csv,text/csv",
    detail: "CSV with cve_id and optional asset/component context columns.",
  },
  {
    label: "Trivy JSON",
    value: "trivy-json",
    accept: ".json,application/json",
    detail: "Trivy vulnerability export in JSON format.",
  },
  {
    label: "Grype JSON",
    value: "grype-json",
    accept: ".json,application/json",
    detail: "Grype vulnerability export in JSON format.",
  },
] as const

type ImportFormat = (typeof mvpImportFormats)[number]["value"]

type TemplateReportFormat =
  | "markdown"
  | "html"
  | "json"
  | "csv"
  | "zip"
  | "attack-navigator"

const reportActionCards: Array<{
  actionLabel: string
  detail: string
  format: string
  icon: typeof FileText
  reportFormat: TemplateReportFormat
  stage: string
  title: string
}> = [
  {
    actionLabel: "Generate Markdown",
    detail:
      "Technical report for analyst handoff, pull requests, and audit notes.",
    format: "Markdown",
    icon: FileText,
    reportFormat: "markdown",
    stage: "VPW-048",
    title: "Markdown Technical Report",
  },
  {
    actionLabel: "Generate HTML",
    detail:
      "Executive browser report with priority summary, evidence links, and safe rendering.",
    format: "HTML",
    icon: FileArchive,
    reportFormat: "html",
    stage: "VPW-049",
    title: "HTML Executive Report",
  },
  {
    actionLabel: "Export JSON",
    detail:
      "Machine-readable findings and analysis data for automation and downstream systems.",
    format: "JSON",
    icon: FileJson,
    reportFormat: "json",
    stage: "VPW-050",
    title: "JSON Findings Export",
  },
  {
    actionLabel: "Export CSV",
    detail:
      "Spreadsheet-friendly findings table for triage, filtering, and stakeholder review.",
    format: "CSV",
    icon: Table2,
    reportFormat: "csv",
    stage: "VPW-050",
    title: "CSV Findings Export",
  },
  {
    actionLabel: "Export Navigator Layer",
    detail:
      "MITRE ATT&CK Navigator JSON with mapped techniques, risk scores, KEV notes, and coverage placeholders.",
    format: "Navigator JSON",
    icon: GitBranch,
    reportFormat: "attack-navigator",
    stage: "VPW-060",
    title: "ATT&CK Navigator Layer",
  },
  {
    actionLabel: "Build Evidence Bundle",
    detail:
      "ZIP package with reports, manifest, source artifacts, and SHA256 checksums.",
    format: "Evidence ZIP",
    icon: FileArchive,
    reportFormat: "zip",
    stage: "VPW-051",
    title: "Evidence Bundle",
  },
]

type ImportWizardState = {
  assetContextFile: File | null
  file: File | null
  inputType: ImportFormat
  vexFile: File | null
}

const defaultImportWizardState: ImportWizardState = {
  assetContextFile: null,
  file: null,
  inputType: "cve-list",
  vexFile: null,
}

type ImportUploadFormData = Parameters<
  typeof ImportsService.importProjectUpload
>[0]["formData"] & {
  vex_file?: string | null
}

type FindingsSort = NonNullable<FindingsReadProjectFindingsData["sort"]>
type FindingsDirection = NonNullable<
  FindingsReadProjectFindingsData["direction"]
>

type KevFilter = "" | "true" | "false"

type FindingFilters = {
  cvssMax: string
  cvssMin: string
  epssMax: string
  epssMin: string
  exposure: "" | AssetExposure
  kev: KevFilter
  ownerService: string
  priority: "" | FindingPriority
  status: "" | FindingStatus
}

const defaultFindingFilters: FindingFilters = {
  cvssMax: "",
  cvssMin: "",
  epssMax: "",
  epssMin: "",
  exposure: "",
  kev: "",
  ownerService: "",
  priority: "",
  status: "",
}

const findingPageSizes = [1, 10, 25, 50] as const

type FindingDetailTab = "overview" | "ttp"
type FindingAttackContext = NonNullable<FindingDetailPublic["attack_context"]>

type WaiverFormState = {
  findingId: string
  cveId: string
  assetId: string
  assetKey: string
  service: string
  owner: string
  reason: string
  expiresAt: string
  reviewAt: string
  approvalRef: string
  ticketUrl: string
}

type FindingWaiverEvidence = {
  approvalRef: string | null
  daysRemaining: string | null
  expiresOn: string | null
  id: string | null
  matchedScope: string | null
  owner: string | null
  reason: string | null
  reviewOn: string | null
  scope: string | null
  status: string | null
  ticketUrl: string | null
}

const emptyWaiverForm: WaiverFormState = {
  approvalRef: "",
  assetId: "",
  assetKey: "",
  cveId: "",
  expiresAt: "",
  findingId: "",
  owner: "",
  reason: "",
  reviewAt: "",
  service: "",
  ticketUrl: "",
}

const findingPriorityOptions: FindingPriority[] = [
  "critical",
  "high",
  "medium",
  "low",
]

const findingStatusOptions: FindingStatus[] = [
  "open",
  "in_review",
  "remediating",
  "fixed",
  "accepted",
  "suppressed",
]

const findingExposureOptions: AssetExposure[] = [
  "internet-facing",
  "internal",
  "private",
  "unknown",
]

const findingSortOptions: { label: string; value: FindingsSort }[] = [
  { label: "Operational", value: "operational" },
  { label: "Priority", value: "priority" },
  { label: "Score", value: "score" },
  { label: "CVE", value: "cve" },
  { label: "Status", value: "status" },
  { label: "EPSS", value: "epss" },
  { label: "CVSS", value: "cvss" },
  { label: "KEV", value: "kev" },
  { label: "Last Seen", value: "last_seen" },
]

const timeline = [
  "Provider snapshot locked",
  "Trivy import normalized",
  "Evidence bundle verified",
]

function priorityCount(
  summary: ProjectDecisionSummaryPublic | null,
  priority: "Critical" | "High" | "Medium" | "Low",
) {
  return summary?.counts_by_priority?.[priority] ?? 0
}

function buildDashboardCards(
  summary: ProjectDecisionSummaryPublic | null,
  providerStatus: ProviderStatusPublic | null,
  loading: boolean,
) {
  const providerFreshness = formatProviderFreshness(providerStatus)
  return [
    {
      label: "Critical",
      value: loading ? "Loading" : String(priorityCount(summary, "Critical")),
      detail: "critical prioritized findings",
      icon: AlertTriangle,
      tone: "critical",
    },
    {
      label: "High",
      value: loading ? "Loading" : String(priorityCount(summary, "High")),
      detail: "high priority findings",
      icon: Gauge,
      tone: "high",
    },
    {
      label: "KEV",
      value: loading ? "Loading" : String(summary?.kev_hits ?? 0),
      detail: "CISA catalog matches",
      icon: ShieldCheck,
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
      label: "Latest Runs",
      value: loading ? "Loading" : formatRunStatus(summary?.latest_run_status),
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
  return rollups?.top_services_by_risk ?? []
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

function formatProviderFreshness(providerStatus: ProviderStatusPublic | null) {
  if (providerStatus === null) {
    return {
      value: "Loading",
      detail: "provider status loading",
      tone: "run",
    }
  }
  if (providerStatus.status === "ok") {
    return {
      value: "Fresh",
      detail:
        providerStatus.cache_age_seconds !== null &&
        providerStatus.cache_age_seconds !== undefined
          ? `${formatCacheAge(providerStatus.cache_age_seconds)} old`
          : providerStatus.snapshot_mode,
      tone: "kev",
    }
  }
  return {
    value: "Needs sync",
    detail:
      providerStatus.last_error ??
      providerStatus.warnings?.[0] ??
      "No snapshot recorded",
    tone: "high",
  }
}

function formatRunStatus(
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

function apiErrorMessage(prefix: string, caught: unknown) {
  if (caught instanceof ApiError) {
    const detail = apiErrorDetail(caught.body)
    return `${prefix}: ${detail ?? caught.message ?? `HTTP ${caught.status}`}`
  }
  return `${prefix}: unexpected client error`
}

function apiErrorDetail(body: unknown) {
  if (typeof body !== "object" || body === null || !("detail" in body)) {
    return null
  }
  const detail = (body as { detail?: unknown }).detail
  if (typeof detail === "string" && detail.trim()) {
    return detail
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) =>
        typeof item === "object" && item !== null && "msg" in item
          ? String((item as { msg?: unknown }).msg)
          : "",
      )
      .filter(Boolean)
    return messages.length > 0 ? messages.join("; ") : "validation failed"
  }
  if (typeof detail === "object" && detail !== null) {
    const record = detail as Record<string, unknown>
    const assetContextError = objectRecord(record.asset_context_error)
    const analysisError = objectRecord(record.analysis_error)
    const vexError = objectRecord(record.vex_error)
    const vexErrorMessage = stringValue(vexError.message)
    if (vexErrorMessage) {
      const detailMessage = stringValue(record.message)
      return detailMessage
        ? `${detailMessage} ${vexErrorMessage}`
        : vexErrorMessage
    }
    return (
      stringValue(record.message) ??
      stringValue(assetContextError.message) ??
      stringValue(analysisError.message) ??
      stringValue(record.error) ??
      null
    )
  }
  return null
}

function analysisRunIdFromError(caught: unknown) {
  if (!(caught instanceof ApiError)) {
    return null
  }
  const detail = errorDetailObject(caught.body)
  const analysisRunId = detail?.analysis_run_id
  return typeof analysisRunId === "string" ? analysisRunId : null
}

function parseErrorsFromError(caught: unknown) {
  if (!(caught instanceof ApiError)) {
    return []
  }
  const detail = errorDetailObject(caught.body)
  const parseErrors = detail?.parse_errors
  return Array.isArray(parseErrors)
    ? parseErrors.filter(isImportParseError)
    : []
}

function errorDetailObject(body: unknown) {
  if (typeof body !== "object" || body === null || !("detail" in body)) {
    return null
  }
  const detail = (body as { detail?: unknown }).detail
  return typeof detail === "object" && detail !== null
    ? (detail as Record<string, unknown>)
    : null
}

function isImportParseError(value: unknown): value is ImportParseErrorPublic {
  return (
    typeof value === "object" &&
    value !== null &&
    "message" in value &&
    typeof (value as { message?: unknown }).message === "string"
  )
}

function importAccept(inputType: ImportFormat) {
  return mvpImportFormats.find((format) => format.value === inputType)?.accept
}

function runStatusLabel(status: AnalysisRunPublic["status"]) {
  return status ? status.replaceAll("_", " ") : "pending"
}

function runStatusTone(status: AnalysisRunPublic["status"]) {
  if (status === "succeeded" || status === "completed") {
    return "succeeded"
  }
  if (status === "failed" || status === "cancelled") {
    return "failed"
  }
  if (status === "completed_with_errors") {
    return "warning"
  }
  return "pending"
}

function runFileLabel(run: {
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

function failedRunCause(
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

function objectRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {}
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : null
}

function optionalText(value: string | null | undefined) {
  return value?.trim() ? value : "N.A."
}

function labelize(value: string | null | undefined) {
  if (!value) {
    return "N.A."
  }
  return value
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (match) => match.toUpperCase())
}

function dateValueFromOffset(days: number) {
  const date = new Date()
  date.setDate(date.getDate() + days)
  return date.toISOString().slice(0, 10)
}

function waiverFormDefaults(): WaiverFormState {
  return {
    ...emptyWaiverForm,
    expiresAt: dateValueFromOffset(30),
    reviewAt: dateValueFromOffset(14),
  }
}

function nullableTrimmed(value: string) {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

function validateWaiverForm(form: WaiverFormState) {
  if (
    !form.findingId.trim() &&
    !form.cveId.trim() &&
    !form.assetId.trim() &&
    !form.assetKey.trim() &&
    !form.service.trim()
  ) {
    return "At least one waiver scope is required."
  }
  if (!form.owner.trim()) {
    return "Owner is required."
  }
  if (!form.reason.trim()) {
    return "Reason is required."
  }
  if (!form.expiresAt.trim()) {
    return "Expires date is required."
  }
  return ""
}

function waiverRequestBody(form: WaiverFormState): WaiverCreate {
  return {
    approval_ref: nullableTrimmed(form.approvalRef),
    asset_id: nullableTrimmed(form.assetId),
    asset_key: nullableTrimmed(form.assetKey),
    cve_id: nullableTrimmed(form.cveId),
    expires_at: nullableTrimmed(form.expiresAt),
    finding_id: nullableTrimmed(form.findingId),
    owner: nullableTrimmed(form.owner),
    reason: nullableTrimmed(form.reason),
    review_at: nullableTrimmed(form.reviewAt),
    service: nullableTrimmed(form.service),
    ticket_url: nullableTrimmed(form.ticketUrl),
  }
}

function waiverScopeLabel(waiver: WaiverPublic) {
  return joinedValues([
    waiver.finding_id ? `Finding ${waiver.finding_id.slice(0, 8)}` : null,
    waiver.cve_id ? `CVE ${waiver.cve_id}` : null,
    waiver.asset_id ? `Asset ID ${waiver.asset_id}` : null,
    waiver.asset_key ? `Asset ${waiver.asset_key}` : null,
    waiver.service ? `Service ${waiver.service}` : null,
  ])
}

function waiverStatusTone(status: string | null | undefined) {
  if (status === "active") {
    return "active"
  }
  if (status === "review_due") {
    return "review-due"
  }
  if (status === "expired") {
    return "expired"
  }
  return "inactive"
}

function findingWaiverEvidence(
  finding: FindingDetailPublic | null,
): FindingWaiverEvidence | null {
  if (!finding?.waived) {
    return null
  }
  const explanation = objectRecord(finding.explanation_json)
  const evidence = objectRecord(finding.evidence_json)
  const nested = {
    ...objectRecord(evidence.waiver),
    ...objectRecord(explanation.waiver),
  }
  const record = {
    ...evidence,
    ...explanation,
    ...nested,
  }
  const status = stringValue(record.waiver_status)
  const id = stringValue(record.waiver_id)
  const reason = stringValue(record.waiver_reason)
  const owner = stringValue(record.waiver_owner)
  const expiresOn = stringValue(record.waiver_expires_on)
  const reviewOn = stringValue(record.waiver_review_on)
  const scope = stringValue(record.waiver_scope)
  const matchedScope = stringValue(record.waiver_matched_scope)
  const approvalRef = stringValue(record.waiver_approval_ref)
  const ticketUrl = stringValue(record.waiver_ticket_url)
  const daysRemaining =
    typeof record.waiver_days_remaining === "number"
      ? String(record.waiver_days_remaining)
      : stringValue(record.waiver_days_remaining)
  if (
    !id &&
    !status &&
    !reason &&
    !owner &&
    !expiresOn &&
    !scope &&
    !approvalRef &&
    !ticketUrl
  ) {
    return null
  }
  return {
    approvalRef,
    daysRemaining,
    expiresOn,
    id,
    matchedScope,
    owner,
    reason,
    reviewOn,
    scope,
    status,
    ticketUrl,
  }
}

function formatNullableNumber(value: number | null | undefined) {
  return value === null || value === undefined ? "N.A." : value.toFixed(1)
}

function formatEpss(value: number | null | undefined) {
  return value === null || value === undefined
    ? "N.A."
    : `${Math.round(value * 1000) / 10}%`
}

function formatKev(value: boolean | null | undefined) {
  return value ? "Yes" : "No"
}

function arrayRecords(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter(
        (entry): entry is Record<string, unknown> =>
          typeof entry === "object" && entry !== null,
      )
    : []
}

function joinedValues(values: Array<string | null | undefined>) {
  const present = values.filter(
    (value): value is string =>
      typeof value === "string" && value.trim() !== "",
  )
  return present.length > 0 ? present.join(" / ") : "N.A."
}

function findingOverviewCards(finding: FindingDetailPublic) {
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
  return (
    stringValue(decisionExplanation.human_readable) ??
    stringValue(decisionExplanation.summary) ??
    explanation?.rationale ??
    finding?.rationale ??
    "No priority explanation has been recorded for this finding."
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

function findingReasonRows(explanation: FindingExplanationPublic | null) {
  const decisionExplanation = objectRecord(explanation?.decision_explanation)
  const reasons = arrayRecords(decisionExplanation.reasons)
  return reasons.map((reason, index) => ({
    detail:
      stringValue(reason.message) ??
      stringValue(reason.description) ??
      stringValue(reason.detail) ??
      stringValue(reason.value) ??
      "Matched decision signal",
    label:
      stringValue(reason.code) ??
      stringValue(reason.signal) ??
      stringValue(reason.source) ??
      `Reason ${index + 1}`,
  }))
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

function attackReviewLabel(value: string | null | undefined) {
  return value ? labelize(value) : "Unreviewed"
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

function findingComponentLabel(finding: FindingPublic) {
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

function findingPriorityTone(finding: FindingPublic) {
  return finding.priority === "critical" || finding.priority === "high"
    ? finding.priority
    : "standard"
}

function metadataRows(value: unknown) {
  return Object.entries(objectRecord(value)).filter(
    ([key, entryValue]) =>
      !key.toLowerCase().includes("path") &&
      entryValue !== null &&
      entryValue !== undefined &&
      typeof entryValue !== "object",
  )
}

function jsonPreview(value: unknown) {
  const record = objectRecord(value)
  return Object.keys(record).length > 0
    ? JSON.stringify(record, null, 2)
    : "No error JSON recorded."
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
  return format.toUpperCase()
}

function reportSizeLabel(sizeBytes: number) {
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

function providerSourceLabel(source: ProviderSourceStatusPublic) {
  return source.name.toUpperCase()
}

function providerSourceState(source: ProviderSourceStatusPublic) {
  if (source.stale) {
    return "stale"
  }
  return source.available ? "available" : "missing"
}

function providerSourceDetail(source: ProviderSourceStatusPublic) {
  if (source.last_error) {
    return source.last_error
  }
  return source.detail ?? "No provider detail recorded."
}

function providerSnapshotId(providerStatus: ProviderStatusPublic | null) {
  const metadata = objectRecord(providerStatus?.snapshot.source_metadata)
  return (
    stringValue(metadata.snapshot_id) ??
    providerStatus?.snapshot.id ??
    "No snapshot ID recorded"
  )
}

function providerSelectedSources(providerStatus: ProviderStatusPublic | null) {
  const selected = providerStatus?.snapshot.selected_sources ?? []
  return selected.length > 0 ? selected.join(", ") : "No sources selected"
}

function providerSourceHashes(providerStatus: ProviderStatusPublic | null) {
  const hashes = providerStatus?.snapshot.source_hashes ?? {}
  const values = Object.entries(hashes).map(([source, hash]) =>
    typeof hash === "string" && hash.trim()
      ? `${source}: ${hash}`
      : `${source}: N.A.`,
  )
  return values.length > 0 ? values.join(" | ") : "No source hashes recorded"
}

function providerDataQualityNotes(providerStatus: ProviderStatusPublic | null) {
  const notes = [
    "Status is based on the latest stored provider snapshot.",
    "Missing, stale, or failed provider evidence is shown as degraded data quality.",
  ]
  if (providerStatus?.snapshot.locked_provider_data) {
    notes.push(
      "Locked replay is active; live provider lookups are not used for this snapshot.",
    )
  }
  return notes
}

export function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const currentPath = normalizeWorkbenchPath(location.pathname)
  const findingDetailId = findingIdFromPath(location.pathname)
  const isFindingDetail = findingDetailId !== null
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
  const [projects, setProjects] = useState<ProjectPublic[]>([])
  const [selectedProjectId, setSelectedProjectId] = useState("")
  const [projectSummary, setProjectSummary] =
    useState<ProjectDecisionSummaryPublic | null>(null)
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
    useState<FindingDetailTab>("overview")
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
  const dashboardLoading = projectListLoading || summaryLoading
  const dashboardCards = buildDashboardCards(
    projectSummary,
    providerStatus,
    dashboardLoading,
  )
  const summaryRows = buildSummaryRows(projectSummary)
  const attackRows = attackSummaryRows(projectAttackSummary)
  const attackTopTechniques = projectAttackSummary?.top_techniques ?? []
  const topServiceRows = governanceServiceRows(projectGovernanceRollups)
  const waiverDebtSummary = waiverDebtSummaryRows(projectGovernanceRollups)
  const waiverDebtItems = waiverDebtRows(projectGovernanceRollups)
  const findingPageStart =
    findingCount === 0 ? 0 : Math.min(findingOffset + 1, findingCount)
  const findingPageEnd = Math.min(findingOffset + findings.length, findingCount)
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
  const detailAttackEmpty = attackContextEmptyState(detailAttackContext)
  const detailWaiverEvidence = findingWaiverEvidence(findingDetail)
  const selectedReportRun =
    projectRuns.find((run) => run.id === selectedRunId) ?? null
  const reportActionsEnabled =
    currentPath === "/reports" &&
    Boolean(selectedReportRun) &&
    isReportableRun(selectedReportRun) &&
    !reportsLoading

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
          setStatusError("Backend adapter unavailable")
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
          projectId: selectedProjectId,
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
          projectId: selectedProjectId,
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
          projectId: selectedProjectId,
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
        !["/imports", "/reports"].includes(currentPath) ||
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
          projectId: selectedProjectId,
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
        return
      }

      setReportsLoading(true)
      setReportsError("")
      try {
        const reportPage = await ReportsService.readRunReports({
          runId: selectedRunId,
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
          RunsService.readRun({ runId: selectedRunId }),
          RunsService.readRunSummary({ runId: selectedRunId }),
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
          projectId: selectedProjectId,
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
          cvssMax: numericFilterValue(findingFilters.cvssMax),
          cvssMin: numericFilterValue(findingFilters.cvssMin),
          direction: findingDirection,
          epssMax: numericFilterValue(findingFilters.epssMax),
          epssMin: numericFilterValue(findingFilters.epssMin),
          exposure: findingFilters.exposure || undefined,
          kev:
            findingFilters.kev === ""
              ? undefined
              : findingFilters.kev === "true",
          limit: findingPageSize,
          offset: findingOffset,
          assetId: findingAssetId || undefined,
          ownerService: findingFilters.ownerService.trim() || undefined,
          priority: findingFilters.priority || undefined,
          projectId: selectedProjectId,
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
    setFindingDetailTab("overview")
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
      try {
        const detail = await FindingsService.readFinding({
          findingId: findingDetailId,
        })
        let explanation: FindingExplanationPublic | null = null
        let explanationWarning = ""
        try {
          explanation = await FindingsService.explainFinding({
            findingId: findingDetailId,
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
        projectId: selectedProjectId,
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

  function updateFindingPageSize(size: number) {
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

  function refreshReports() {
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
        runId: selectedRunId,
        requestBody: { format },
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
    setReportActionError("")
    setReportActionMessage("")
    try {
      const verification = await ReportsService.verifyReport({
        reportId: report.id,
      })
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
        requestBody: projectRequestBody(createProjectForm),
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
        projectId: editProjectId,
        requestBody: projectRequestBody(editProjectForm),
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
      await ProjectsService.deleteProject({ projectId: project.id })
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
              asset_context_file: selectedAssetContextFile as unknown as string,
            }
          : {}),
        ...(selectedVexFile
          ? {
              vex_file: selectedVexFile as unknown as string,
            }
          : {}),
        file: selectedFile as unknown as string,
        input_type: importWizard.inputType,
      }
      const run = await ImportsService.importProjectUpload({
        projectId: importProjectId,
        formData: uploadFormData,
      })
      setImportRun(run)
      const summary = await RunsService.readRunSummary({ runId: run.id })
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
          const summary = await RunsService.readRunSummary({ runId })
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
        projectId: selectedProjectId,
        requestBody: waiverRequestBody(waiverForm),
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
        waiverId: waiver.id,
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

  async function signOut() {
    clearAccessToken()
    await navigate({ to: "/login" })
  }

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Workbench sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            VP
          </div>
          <div>
            <strong>Vuln Prioritizer</strong>
            <span>Workbench</span>
          </div>
        </div>
        <nav className="nav-list" aria-label="Workbench navigation">
          {workbenchNavigation.map((entry) => (
            <Link
              aria-current={
                isActivePath(currentPath, entry.to) ? "page" : undefined
              }
              className={
                isActivePath(currentPath, entry.to)
                  ? "nav-item active"
                  : "nav-item"
              }
              key={entry.label}
              to={entry.to}
            >
              <entry.icon aria-hidden="true" size={18} />
              <span>{entry.label}</span>
            </Link>
          ))}
        </nav>
        <div className="sidebar-footer">
          <KeyRound aria-hidden="true" size={18} />
          <span>{currentUserLabel(currentUser)}</span>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">{routeDetail.eyebrow}</span>
            <h1>{routeDetail.title}</h1>
          </div>
          <div
            className="status-strip"
            role="status"
            aria-label="Workspace health"
          >
            <span className="status-dot" aria-hidden="true" />
            <span>
              {status?.status === "ok" ? "Backend adapter online" : statusError}
            </span>
          </div>
          <button
            className="icon-button"
            type="button"
            aria-label="Sign out"
            onClick={signOut}
          >
            <LogOut aria-hidden="true" size={18} />
          </button>
        </header>

        <section
          className="template-status"
          aria-label="Template backend status"
        >
          <div>
            <span>Application</span>
            <strong>{status?.app ?? "Vuln Prioritizer Workbench"}</strong>
          </div>
          <div>
            <span>Core</span>
            <strong>
              {status?.core_package ?? "vuln_prioritizer"}{" "}
              {status?.core_version ?? ""}
            </strong>
          </div>
          <div>
            <span>Migration</span>
            <strong>{status?.migration.phase ?? "loading"}</strong>
          </div>
          <div>
            <span>Legacy mount</span>
            <strong>
              {status?.migration.legacy_workbench_mounted
                ? "enabled"
                : "disabled"}
            </strong>
          </div>
        </section>

        {currentPath === "/" ? (
          <>
            <section
              className="dashboard-toolbar"
              aria-label="Dashboard project context"
            >
              <label className="project-selector">
                <span>Current project</span>
                <select
                  aria-label="Current project"
                  disabled={dashboardLoading || projects.length === 0}
                  onChange={(event) => setSelectedProjectId(event.target.value)}
                  value={selectedProjectId}
                >
                  {projects.length === 0 ? (
                    <option value="">No projects</option>
                  ) : null}
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
              </label>
              <div className="project-context">
                <span>Summary source</span>
                <strong>
                  {selectedProject?.name ??
                    (projectListLoading ? "Loading" : "No project selected")}
                </strong>
              </div>
            </section>

            <section className="metric-grid" aria-label="Dashboard summary">
              {dashboardCards.map((card) => (
                <article
                  aria-label={`${card.label} summary card`}
                  className={`metric-card tone-${card.tone}`}
                  key={card.label}
                >
                  <card.icon aria-hidden="true" size={20} />
                  <div>
                    <span>{card.label}</span>
                    <strong>{card.value}</strong>
                    <small>{card.detail}</small>
                  </div>
                </article>
              ))}
            </section>
          </>
        ) : null}

        {currentPath === "/settings" ? (
          <section className="settings-summary" aria-label="User Settings">
            {settingsSummary(currentUser).map((entry) => (
              <div key={entry.label}>
                <span>{entry.label}</span>
                <strong>{entry.value}</strong>
              </div>
            ))}
          </section>
        ) : null}

        <section
          className={
            currentPath === "/findings" ||
            currentPath === "/waivers" ||
            currentPath === "/providers" ||
            currentPath === "/reports"
              ? "content-grid wide-workspace"
              : "content-grid"
          }
        >
          <div className="work-panel">
            <div className="panel-header">
              <div>
                <h2>
                  {isFindingDetail ? "Finding Detail" : routeDetail.panelTitle}
                </h2>
                <span>
                  {isFindingDetail
                    ? "Overview, source occurrences, and decision rationale"
                    : routeDetail.panelDetail}
                </span>
              </div>
              <button
                className="icon-button"
                type="button"
                aria-label={
                  currentPath === "/projects"
                    ? "Refresh projects"
                    : isFindingDetail
                      ? "Refresh finding detail"
                      : currentPath === "/findings"
                        ? "Refresh findings"
                        : currentPath === "/waivers"
                          ? "Refresh waivers"
                          : currentPath === "/providers"
                            ? "Refresh provider status"
                            : currentPath === "/reports"
                              ? "Refresh reports"
                              : "Refresh queue"
                }
                onClick={() => {
                  if (currentPath === "/projects") {
                    void refreshProjects(selectedProjectId)
                  }
                  if (isFindingDetail) {
                    refreshFindingDetail()
                  } else if (currentPath === "/findings") {
                    refreshFindings()
                  } else if (currentPath === "/waivers") {
                    refreshWaivers()
                  } else if (currentPath === "/providers") {
                    void refreshProviderStatus()
                  } else if (currentPath === "/reports") {
                    void refreshProjectRuns(selectedRunId)
                    refreshReports()
                  }
                }}
              >
                <Activity aria-hidden="true" size={18} />
              </button>
            </div>

            {currentPath === "/projects" ? (
              <section
                className="projects-workflow"
                aria-label="Projects workflow"
              >
                <section
                  className="project-form-panel"
                  aria-label="Create Project form"
                >
                  <h3>Create Project</h3>
                  <form onSubmit={createProject}>
                    <label>
                      <span>Project name</span>
                      <input
                        maxLength={255}
                        onChange={(event) =>
                          setCreateProjectForm((form) => ({
                            ...form,
                            name: event.target.value,
                          }))
                        }
                        value={createProjectForm.name}
                      />
                    </label>
                    <label>
                      <span>Description</span>
                      <textarea
                        maxLength={4096}
                        onChange={(event) =>
                          setCreateProjectForm((form) => ({
                            ...form,
                            description: event.target.value,
                          }))
                        }
                        rows={3}
                        value={createProjectForm.description}
                      />
                    </label>
                    {createProjectError ? (
                      <p className="form-error">{createProjectError}</p>
                    ) : null}
                    <button
                      className="primary-action"
                      disabled={projectActionLoading}
                      type="submit"
                    >
                      Create Project
                    </button>
                  </form>
                </section>

                {projectActionError ? (
                  <p className="dashboard-alert" role="alert">
                    {projectActionError}
                  </p>
                ) : null}
                {projectActionMessage ? (
                  <p className="dashboard-state" role="status">
                    {projectActionMessage}
                  </p>
                ) : null}

                <section
                  className="project-list-panel"
                  aria-label="Projects list"
                >
                  {projectListLoading ? (
                    <p className="dashboard-state" role="status">
                      Loading projects
                    </p>
                  ) : null}
                  {!projectListLoading && projects.length === 0 ? (
                    <section
                      className="dashboard-empty"
                      aria-label="Projects empty state"
                    >
                      <h3>No projects yet</h3>
                      <p>
                        Create the first project to start importing CVEs and
                        findings.
                      </p>
                    </section>
                  ) : null}
                  {projects.length > 0 ? (
                    <ul className="project-list">
                      {projects.map((project) => (
                        <li key={project.id}>
                          <button
                            aria-current={
                              project.id === selectedProjectId
                                ? "true"
                                : undefined
                            }
                            className={
                              project.id === selectedProjectId
                                ? "project-list-item active"
                                : "project-list-item"
                            }
                            onClick={() => {
                              setSelectedProjectId(project.id)
                              setDeleteConfirmed(false)
                              setEditProjectId("")
                            }}
                            type="button"
                          >
                            <strong>{project.name}</strong>
                            <span>
                              {project.description || "No description"}
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </section>

                {selectedProject ? (
                  <section
                    className="project-detail"
                    aria-label="Project detail"
                  >
                    <div className="project-detail-header">
                      <div>
                        <span>Selected project</span>
                        <h3>{selectedProject.name}</h3>
                        <p>{selectedProject.description || "No description"}</p>
                      </div>
                      <button
                        className="secondary-action"
                        onClick={() => startEditProject(selectedProject)}
                        type="button"
                      >
                        Edit
                      </button>
                    </div>
                    <dl className="project-meta">
                      <div>
                        <dt>Created</dt>
                        <dd>{formatDateTime(selectedProject.created_at)}</dd>
                      </div>
                      <div>
                        <dt>Updated</dt>
                        <dd>{formatDateTime(selectedProject.updated_at)}</dd>
                      </div>
                    </dl>

                    {editProjectId === selectedProject.id ? (
                      <form
                        className="project-edit-form"
                        onSubmit={saveProject}
                      >
                        <label>
                          <span>Edit project name</span>
                          <input
                            maxLength={255}
                            onChange={(event) =>
                              setEditProjectForm((form) => ({
                                ...form,
                                name: event.target.value,
                              }))
                            }
                            value={editProjectForm.name}
                          />
                        </label>
                        <label>
                          <span>Edit description</span>
                          <textarea
                            maxLength={4096}
                            onChange={(event) =>
                              setEditProjectForm((form) => ({
                                ...form,
                                description: event.target.value,
                              }))
                            }
                            rows={3}
                            value={editProjectForm.description}
                          />
                        </label>
                        <div className="project-actions">
                          <button
                            className="primary-action"
                            disabled={projectActionLoading}
                            type="submit"
                          >
                            Save Project
                          </button>
                          <button
                            className="secondary-action"
                            onClick={() => setEditProjectId("")}
                            type="button"
                          >
                            Cancel
                          </button>
                        </div>
                      </form>
                    ) : null}

                    <div className="delete-confirmation">
                      <label>
                        <input
                          checked={deleteConfirmed}
                          onChange={(event) =>
                            setDeleteConfirmed(event.target.checked)
                          }
                          type="checkbox"
                        />
                        <span>Confirm deletion for this project</span>
                      </label>
                      <button
                        className="danger-action"
                        disabled={projectActionLoading || !deleteConfirmed}
                        onClick={() => void deleteProject(selectedProject)}
                        type="button"
                      >
                        Delete Project
                      </button>
                    </div>
                  </section>
                ) : null}
              </section>
            ) : currentPath === "/imports" ? (
              <section className="import-wizard" aria-label="Import wizard">
                <form className="import-form" onSubmit={submitImport}>
                  <label>
                    <span>Project</span>
                    <select
                      aria-label="Import project"
                      disabled={projectListLoading || projects.length === 0}
                      name="importProject"
                      onChange={(event) =>
                        setSelectedProjectId(event.target.value)
                      }
                      value={selectedProjectId}
                    >
                      {projects.length === 0 ? (
                        <option value="">No projects</option>
                      ) : null}
                      {projects.map((project) => (
                        <option key={project.id} value={project.id}>
                          {project.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Input type</span>
                    <select
                      aria-label="Input type"
                      onChange={(event) =>
                        setImportWizard((state) => ({
                          ...state,
                          inputType: event.target.value as ImportFormat,
                        }))
                      }
                      value={importWizard.inputType}
                    >
                      {mvpImportFormats.map((format) => (
                        <option key={format.value} value={format.value}>
                          {format.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Import file</span>
                    <input
                      accept={importAccept(importWizard.inputType)}
                      aria-label="Import file"
                      name="importFile"
                      onChange={(event) =>
                        setImportWizard((state) => ({
                          ...state,
                          file: event.target.files?.[0] ?? null,
                        }))
                      }
                      type="file"
                    />
                  </label>
                  <label>
                    <span>Asset context CSV</span>
                    <input
                      accept=".csv,text/csv"
                      aria-label="Asset context CSV"
                      name="assetContextFile"
                      onChange={(event) =>
                        setImportWizard((state) => ({
                          ...state,
                          assetContextFile: event.target.files?.[0] ?? null,
                        }))
                      }
                      type="file"
                    />
                  </label>
                  <label>
                    <span>OpenVEX/VEX JSON</span>
                    <input
                      accept=".json,application/json"
                      aria-label="OpenVEX/VEX JSON"
                      name="vexFile"
                      onChange={(event) =>
                        setImportWizard((state) => ({
                          ...state,
                          vexFile: event.target.files?.[0] ?? null,
                        }))
                      }
                      type="file"
                    />
                  </label>
                  <button
                    className="primary-action"
                    disabled={importLoading || projects.length === 0}
                    type="submit"
                  >
                    {importLoading ? "Uploading" : "Upload Import"}
                  </button>
                </form>

                <section
                  className="format-list"
                  aria-label="Supported MVP formats"
                >
                  {mvpImportFormats.map((format) => (
                    <article key={format.value}>
                      <strong>{format.label}</strong>
                      <span>{format.value}</span>
                      <p>{format.detail}</p>
                    </article>
                  ))}
                </section>

                <section
                  className="security-notes"
                  aria-label="Upload security notes"
                >
                  <h3>Upload Security Notes</h3>
                  <ul>
                    <li>Files are parsed locally by the Workbench backend.</li>
                    <li>
                      Uploads must match the selected format and extension.
                    </li>
                    <li>
                      Optional asset context uploads must be CSV files with
                      target and asset_id columns.
                    </li>
                    <li>
                      Optional OpenVEX/VEX sidecars must be JSON documents.
                    </li>
                    <li>Filename/path traversal is rejected before storage.</li>
                    <li>
                      The import wizard does not run scanners or network probes.
                    </li>
                  </ul>
                </section>

                {importError ? (
                  <p className="dashboard-alert" role="alert">
                    {importError}
                  </p>
                ) : null}
                {importLoading ? (
                  <p className="dashboard-state" role="status">
                    Uploading and parsing import file
                  </p>
                ) : null}

                {projects.length === 0 && !projectListLoading ? (
                  <section
                    className="dashboard-empty"
                    aria-label="Import empty state"
                  >
                    <h3>No project available</h3>
                    <p>Create a project before uploading import files.</p>
                    <Link className="primary-action" to="/projects">
                      Projects
                    </Link>
                  </section>
                ) : null}

                {importRunSummary ? (
                  <section className="import-result" aria-label="Import result">
                    <div>
                      <span>Run status</span>
                      <strong>{runStatusLabel(importRunSummary.status)}</strong>
                    </div>
                    <div>
                      <span>Created findings</span>
                      <strong>{importRunSummary.created_findings ?? 0}</strong>
                    </div>
                    <div>
                      <span>Updated findings</span>
                      <strong>{importRunSummary.updated_findings ?? 0}</strong>
                    </div>
                    <div>
                      <span>Ignored lines</span>
                      <strong>{importRunSummary.ignored_lines ?? 0}</strong>
                    </div>
                  </section>
                ) : importRun ? (
                  <section className="import-result" aria-label="Import result">
                    <div>
                      <span>Run status</span>
                      <strong>{runStatusLabel(importRun.status)}</strong>
                    </div>
                    <div>
                      <span>Run id</span>
                      <strong>{importRun.id.slice(0, 8)}</strong>
                    </div>
                  </section>
                ) : null}

                {importParseErrors.length > 0 ? (
                  <section className="parse-errors" aria-label="Parser errors">
                    <h3>Parser errors</h3>
                    <table>
                      <thead>
                        <tr>
                          <th>Line</th>
                          <th>Field</th>
                          <th>Value</th>
                          <th>Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {importParseErrors.map((error) => (
                          <tr
                            key={[
                              error.filename,
                              error.line,
                              error.field,
                              error.value,
                              error.message,
                            ].join(":")}
                          >
                            <td>{error.line ?? "N.A."}</td>
                            <td>{error.field ?? "N.A."}</td>
                            <td>{error.value ?? "N.A."}</td>
                            <td>{error.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </section>
                ) : null}

                <section className="runs-browser" aria-label="Import runs">
                  <div className="runs-list-panel">
                    <div className="runs-section-header">
                      <div>
                        <h3>Historical Runs</h3>
                        <span>
                          {selectedProject
                            ? selectedProject.name
                            : "No project selected"}
                        </span>
                      </div>
                      <button
                        className="secondary-action"
                        disabled={runsLoading || !selectedProjectId}
                        onClick={() => void refreshProjectRuns(selectedRunId)}
                        type="button"
                      >
                        Refresh
                      </button>
                    </div>
                    {runsError ? (
                      <p className="dashboard-alert" role="alert">
                        {runsError}
                      </p>
                    ) : null}
                    {runsLoading ? (
                      <p className="dashboard-state" role="status">
                        Loading import runs
                      </p>
                    ) : null}
                    {!runsLoading && projectRuns.length === 0 ? (
                      <section
                        className="dashboard-empty compact-empty"
                        aria-label="Runs empty state"
                      >
                        <h3>No import runs yet</h3>
                        <p>Upload a supported file to create run history.</p>
                      </section>
                    ) : null}
                    {projectRuns.length > 0 ? (
                      <ul className="runs-list">
                        {projectRuns.map((run) => (
                          <li key={run.id}>
                            <button
                              aria-current={
                                selectedRunId === run.id ? "true" : undefined
                              }
                              className={
                                selectedRunId === run.id
                                  ? "run-list-item active"
                                  : "run-list-item"
                              }
                              onClick={() => setSelectedRunId(run.id)}
                              type="button"
                            >
                              <span
                                className={`run-status ${runStatusTone(
                                  run.status,
                                )}`}
                              >
                                {runStatusLabel(run.status)}
                              </span>
                              <strong>{runFileLabel(run)}</strong>
                              <span>{run.input_type}</span>
                              <small>
                                {formatDateTime(run.started_at ?? "")}
                              </small>
                            </button>
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </div>

                  <section className="run-detail-panel" aria-label="Run detail">
                    <div className="runs-section-header">
                      <div>
                        <h3>Run Detail</h3>
                        <span>
                          {selectedRunId
                            ? selectedRunId.slice(0, 8)
                            : "No run selected"}
                        </span>
                      </div>
                      <Link className="secondary-action" to="/findings">
                        Findings
                      </Link>
                    </div>
                    {runDetailError ? (
                      <p className="dashboard-alert" role="alert">
                        {runDetailError}
                      </p>
                    ) : null}
                    {runDetailLoading ? (
                      <p className="dashboard-state" role="status">
                        Loading run detail
                      </p>
                    ) : null}
                    {!runDetailLoading && !selectedRunId ? (
                      <section
                        className="dashboard-empty compact-empty"
                        aria-label="No run selected"
                      >
                        <h3>No run selected</h3>
                        <p>
                          Select a historical import run to inspect details.
                        </p>
                      </section>
                    ) : null}
                    {selectedRun && selectedRunSummary ? (
                      <>
                        <dl className="run-facts">
                          <div>
                            <dt>Status</dt>
                            <dd>
                              <span
                                className={`run-status ${runStatusTone(
                                  selectedRunSummary.status,
                                )}`}
                              >
                                {runStatusLabel(selectedRunSummary.status)}
                              </span>
                            </dd>
                          </div>
                          <div>
                            <dt>Input type</dt>
                            <dd>{selectedRunSummary.input_type}</dd>
                          </div>
                          <div>
                            <dt>Filename</dt>
                            <dd>{runFileLabel(selectedRunSummary)}</dd>
                          </div>
                          <div>
                            <dt>Started</dt>
                            <dd>
                              {formatDateTime(selectedRunSummary.started_at)}
                            </dd>
                          </div>
                          <div>
                            <dt>Finished</dt>
                            <dd>
                              {selectedRunSummary.finished_at
                                ? formatDateTime(selectedRunSummary.finished_at)
                                : "N.A."}
                            </dd>
                          </div>
                          <div>
                            <dt>Provider snapshot</dt>
                            <dd>
                              {selectedRunSummary.provider_snapshot_id ??
                                "N.A."}
                            </dd>
                          </div>
                        </dl>

                        <section className="run-counts" aria-label="Run counts">
                          <div>
                            <span>Created</span>
                            <strong>
                              {selectedRunSummary.created_findings ?? 0}
                            </strong>
                          </div>
                          <div>
                            <span>Updated</span>
                            <strong>
                              {selectedRunSummary.updated_findings ?? 0}
                            </strong>
                          </div>
                          <div>
                            <span>Findings</span>
                            <strong>
                              {selectedRunSummary.finding_count ?? 0}
                            </strong>
                          </div>
                          <div>
                            <span>Ignored</span>
                            <strong>
                              {selectedRunSummary.ignored_lines ?? 0}
                            </strong>
                          </div>
                        </section>

                        {selectedRunSummary.status === "failed" ? (
                          <section
                            className="failure-cause"
                            aria-label="Run failure cause"
                          >
                            <h4>Failure Cause</h4>
                            <p>
                              {failedRunCause(selectedRun, selectedRunSummary)}
                            </p>
                            <pre>
                              {jsonPreview(selectedRunSummary.error_json)}
                            </pre>
                          </section>
                        ) : null}

                        <section
                          className="upload-metadata"
                          aria-label="Upload metadata"
                        >
                          <h4>Upload Metadata</h4>
                          {metadataRows(selectedRunSummary.input_upload)
                            .length > 0 ? (
                            <dl>
                              {metadataRows(
                                selectedRunSummary.input_upload,
                              ).map(([key, value]) => (
                                <div key={key}>
                                  <dt>{key}</dt>
                                  <dd>{String(value)}</dd>
                                </div>
                              ))}
                            </dl>
                          ) : (
                            <p>No upload metadata recorded.</p>
                          )}
                        </section>

                        <section
                          className="parse-errors"
                          aria-label="Run parser errors"
                        >
                          <h3>Parse Errors</h3>
                          {(selectedRunSummary.parse_errors ?? []).length >
                          0 ? (
                            <table>
                              <thead>
                                <tr>
                                  <th>Line</th>
                                  <th>Field</th>
                                  <th>Value</th>
                                  <th>Message</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(selectedRunSummary.parse_errors ?? []).map(
                                  (error) => (
                                    <tr
                                      key={[
                                        error.filename,
                                        error.line,
                                        error.field,
                                        error.value,
                                        error.message,
                                      ].join(":")}
                                    >
                                      <td>{error.line ?? "N.A."}</td>
                                      <td>{error.field ?? "N.A."}</td>
                                      <td>{error.value ?? "N.A."}</td>
                                      <td>{error.message}</td>
                                    </tr>
                                  ),
                                )}
                              </tbody>
                            </table>
                          ) : (
                            <p>No parser errors recorded.</p>
                          )}
                        </section>
                      </>
                    ) : null}
                  </section>
                </section>
              </section>
            ) : isWaiversPage ? (
              <section
                className="waivers-workflow"
                aria-label="Waivers workspace"
              >
                <section
                  className="waiver-toolbar"
                  aria-label="Waiver project context"
                >
                  <label>
                    <span>Project</span>
                    <select
                      aria-label="Waivers project"
                      disabled={projectListLoading || projects.length === 0}
                      onChange={(event) =>
                        setSelectedProjectId(event.target.value)
                      }
                      value={selectedProjectId}
                    >
                      {projects.length === 0 ? (
                        <option value="">No projects</option>
                      ) : null}
                      {projects.map((project) => (
                        <option key={project.id} value={project.id}>
                          {project.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div>
                    <span>Register</span>
                    <strong>{selectedProject?.name ?? "No project"}</strong>
                  </div>
                  <div>
                    <span>Open waivers</span>
                    <strong>{waivers.length}</strong>
                  </div>
                  <div>
                    <span>Accepted findings</span>
                    <strong>
                      {projectGovernanceRollups?.waiver_debt
                        ?.accepted_finding_count ??
                        waivers.reduce(
                          (total, waiver) =>
                            total + (waiver.matched_findings ?? 0),
                          0,
                        )}
                    </strong>
                  </div>
                </section>

                {waiversError ? (
                  <p className="dashboard-alert" role="alert">
                    {waiversError}
                  </p>
                ) : null}
                {waiverActionError ? (
                  <p className="dashboard-alert" role="alert">
                    {waiverActionError}
                  </p>
                ) : null}
                {waiverActionMessage ? (
                  <p className="dashboard-success" role="status">
                    {waiverActionMessage}
                  </p>
                ) : null}

                <section
                  className="waiver-debt-section"
                  aria-label="Waiver Debt"
                >
                  <div className="detail-section-heading">
                    <h3>Waiver Debt</h3>
                    <span>Expired, review-due, and expiring accepted risk</span>
                  </div>
                  {governanceError ? (
                    <p className="dashboard-alert" role="alert">
                      {governanceError}
                    </p>
                  ) : null}
                  {governanceLoading ? (
                    <p className="dashboard-state" role="status">
                      Loading waiver debt
                    </p>
                  ) : null}
                  <dl className="governance-debt-grid">
                    {waiverDebtSummary.map((row) => (
                      <div key={row.label}>
                        <dt>{row.label}</dt>
                        <dd>
                          <strong>{row.value}</strong>
                          <span>{row.detail}</span>
                        </dd>
                      </div>
                    ))}
                  </dl>
                  {!governanceLoading &&
                  !governanceError &&
                  waiverDebtItems.length === 0 ? (
                    <p className="attack-summary-empty">
                      No waiver debt is currently recorded for this project.
                    </p>
                  ) : null}
                  {waiverDebtItems.length > 0 ? (
                    <ul className="waiver-debt-items">
                      {waiverDebtItems.map((item) => (
                        <li key={item.id}>
                          <div>
                            <strong>{item.scope}</strong>
                            <span
                              className={`waiver-status ${waiverStatusTone(
                                item.status,
                              )}`}
                            >
                              {labelize(item.status)}
                            </span>
                          </div>
                          <small>
                            Owner {item.owner} / Matched{" "}
                            {item.matched_findings ?? 0} / Expires{" "}
                            {item.expires_at} / Days {item.days_remaining}
                          </small>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </section>

                <section
                  className="waiver-create-panel"
                  aria-label="Create waiver"
                >
                  <div className="detail-section-heading">
                    <h3>Create waiver</h3>
                    <span>Scope to finding, CVE, asset, or service</span>
                  </div>
                  <form className="waiver-form" onSubmit={createWaiver}>
                    <label>
                      <span>CVE ID</span>
                      <input
                        aria-label="Waiver CVE ID"
                        onChange={(event) =>
                          updateWaiverFormField("cveId", event.target.value)
                        }
                        placeholder="CVE-2024-3094"
                        value={waiverForm.cveId}
                      />
                    </label>
                    <label>
                      <span>Finding ID</span>
                      <input
                        aria-label="Waiver finding ID"
                        onChange={(event) =>
                          updateWaiverFormField("findingId", event.target.value)
                        }
                        placeholder="Optional UUID"
                        value={waiverForm.findingId}
                      />
                    </label>
                    <label>
                      <span>Asset ID</span>
                      <input
                        aria-label="Waiver asset ID"
                        onChange={(event) =>
                          updateWaiverFormField("assetId", event.target.value)
                        }
                        placeholder="Optional UUID"
                        value={waiverForm.assetId}
                      />
                    </label>
                    <label>
                      <span>Asset key</span>
                      <input
                        aria-label="Waiver asset key"
                        onChange={(event) =>
                          updateWaiverFormField("assetKey", event.target.value)
                        }
                        placeholder="payments-api"
                        value={waiverForm.assetKey}
                      />
                    </label>
                    <label>
                      <span>Service</span>
                      <input
                        aria-label="Waiver service"
                        onChange={(event) =>
                          updateWaiverFormField("service", event.target.value)
                        }
                        placeholder="checkout"
                        value={waiverForm.service}
                      />
                    </label>
                    <label>
                      <span>Owner</span>
                      <input
                        aria-label="Waiver owner"
                        onChange={(event) =>
                          updateWaiverFormField("owner", event.target.value)
                        }
                        placeholder="risk-owner"
                        value={waiverForm.owner}
                      />
                    </label>
                    <label className="wide-field">
                      <span>Reason</span>
                      <textarea
                        aria-label="Waiver reason"
                        onChange={(event) =>
                          updateWaiverFormField("reason", event.target.value)
                        }
                        rows={3}
                        value={waiverForm.reason}
                      />
                    </label>
                    <label>
                      <span>Expires</span>
                      <input
                        aria-label="Waiver expires at"
                        onChange={(event) =>
                          updateWaiverFormField("expiresAt", event.target.value)
                        }
                        type="date"
                        value={waiverForm.expiresAt}
                      />
                    </label>
                    <label>
                      <span>Review</span>
                      <input
                        aria-label="Waiver review at"
                        onChange={(event) =>
                          updateWaiverFormField("reviewAt", event.target.value)
                        }
                        type="date"
                        value={waiverForm.reviewAt}
                      />
                    </label>
                    <label>
                      <span>Approval</span>
                      <input
                        aria-label="Waiver approval reference"
                        onChange={(event) =>
                          updateWaiverFormField(
                            "approvalRef",
                            event.target.value,
                          )
                        }
                        placeholder="CAB-064"
                        value={waiverForm.approvalRef}
                      />
                    </label>
                    <label>
                      <span>Ticket URL</span>
                      <input
                        aria-label="Waiver ticket URL"
                        onChange={(event) =>
                          updateWaiverFormField("ticketUrl", event.target.value)
                        }
                        placeholder="https://tracker.example/..."
                        value={waiverForm.ticketUrl}
                      />
                    </label>
                    <button
                      className="primary-action"
                      disabled={
                        waiverActionLoading ||
                        projectListLoading ||
                        projects.length === 0
                      }
                      type="submit"
                    >
                      Create waiver
                    </button>
                  </form>
                </section>

                <section
                  className="waiver-register"
                  aria-label="Risk acceptance register"
                >
                  <div className="detail-section-heading">
                    <h3>Risk acceptance register</h3>
                    <span>
                      Accepted risk remains visible after create and expiry.
                    </span>
                  </div>
                  {waiversLoading ? (
                    <p className="dashboard-state" role="status">
                      Loading waivers
                    </p>
                  ) : null}
                  {!waiversLoading && waivers.length === 0 ? (
                    <section
                      className="dashboard-empty"
                      aria-label="No waivers empty state"
                    >
                      <h3>No waivers yet</h3>
                      <p>
                        Create a waiver to mark accepted risk without deleting
                        or hiding the finding.
                      </p>
                    </section>
                  ) : null}
                  {waivers.length > 0 ? (
                    <div className="table-wrap">
                      <table aria-label="Waivers table">
                        <thead>
                          <tr>
                            <th>Scope</th>
                            <th>Owner</th>
                            <th>Status</th>
                            <th>Expires</th>
                            <th>Review</th>
                            <th>Matched</th>
                            <th>Approval</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {waivers.map((waiver) => (
                            <tr key={waiver.id}>
                              <td>
                                <span className="finding-primary">
                                  {waiverScopeLabel(waiver)}
                                </span>
                                <small>{waiver.reason}</small>
                              </td>
                              <td>{waiver.owner}</td>
                              <td>
                                <span
                                  className={`waiver-status ${waiverStatusTone(
                                    waiver.status,
                                  )}`}
                                >
                                  {labelize(waiver.status)}
                                </span>
                              </td>
                              <td>{waiver.expires_at}</td>
                              <td>{waiver.review_at ?? "N.A."}</td>
                              <td>{waiver.matched_findings ?? 0}</td>
                              <td>
                                {waiver.approval_ref ??
                                  waiver.ticket_url ??
                                  "N.A."}
                              </td>
                              <td>
                                <button
                                  className="secondary-action"
                                  disabled={
                                    waiverActionLoading ||
                                    waiver.status === "expired"
                                  }
                                  onClick={() => void expireWaiver(waiver)}
                                  type="button"
                                >
                                  Expire
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : null}
                </section>
              </section>
            ) : isFindingDetail ? (
              <section
                className="finding-detail-workflow"
                aria-label="Finding detail"
              >
                <div className="finding-detail-backbar">
                  <Link
                    className="secondary-action finding-back-link"
                    to="/findings"
                  >
                    <ArrowLeft aria-hidden="true" size={16} />
                    <span>Back to Findings</span>
                  </Link>
                </div>

                {findingDetailError ? (
                  <p className="dashboard-alert" role="alert">
                    {findingDetailError}
                  </p>
                ) : null}
                {findingExplanationWarning ? (
                  <p className="dashboard-alert" role="alert">
                    {findingExplanationWarning}
                  </p>
                ) : null}
                {findingDetailLoading ? (
                  <p className="dashboard-state" role="status">
                    Loading finding detail
                  </p>
                ) : null}

                {!findingDetailLoading &&
                !findingDetailError &&
                findingDetail ? (
                  <>
                    <section
                      className="finding-detail-header"
                      aria-label="Finding detail header"
                    >
                      <div>
                        <span>Finding</span>
                        <h3>{findingDetail.cve_id}</h3>
                      </div>
                      <div className="finding-detail-badges">
                        <span
                          className={`severity ${
                            findingDetail.priority ?? "low"
                          }`}
                        >
                          {labelize(findingDetail.priority)}
                        </span>
                        <span className="status-pill">
                          {labelize(findingDetail.status)}
                        </span>
                      </div>
                    </section>

                    <section
                      className="finding-detail-overview"
                      aria-label="Finding overview"
                    >
                      {findingOverviewCards(findingDetail).map((card) => (
                        <article
                          className="finding-overview-card"
                          key={card.label}
                        >
                          <span>{card.label}</span>
                          <strong>{card.value}</strong>
                          <small>{card.detail}</small>
                        </article>
                      ))}
                    </section>

                    <div
                      className="finding-detail-tabs"
                      role="tablist"
                      aria-label="Finding detail tabs"
                    >
                      <button
                        aria-controls="finding-overview-panel"
                        aria-selected={findingDetailTab === "overview"}
                        className={
                          findingDetailTab === "overview" ? "active" : ""
                        }
                        id="finding-overview-tab"
                        onClick={() => setFindingDetailTab("overview")}
                        role="tab"
                        type="button"
                      >
                        Overview
                      </button>
                      <button
                        aria-controls="finding-ttp-panel"
                        aria-selected={findingDetailTab === "ttp"}
                        className={findingDetailTab === "ttp" ? "active" : ""}
                        id="finding-ttp-tab"
                        onClick={() => setFindingDetailTab("ttp")}
                        role="tab"
                        type="button"
                      >
                        TTP Context
                      </button>
                    </div>

                    {findingDetailTab === "overview" ? (
                      <div
                        className="finding-detail-tab-panel"
                        id="finding-overview-panel"
                        role="tabpanel"
                        aria-labelledby="finding-overview-tab"
                      >
                        {detailWaiverEvidence ? (
                          <section
                            className="accepted-risk-panel"
                            aria-label="Accepted risk"
                          >
                            <div className="detail-section-heading">
                              <h3>Accepted risk</h3>
                              <span>
                                {labelize(detailWaiverEvidence.status)}
                              </span>
                            </div>
                            <dl className="project-meta">
                              <div>
                                <dt>Owner</dt>
                                <dd>
                                  {optionalText(detailWaiverEvidence.owner)}
                                </dd>
                              </div>
                              <div>
                                <dt>Reason</dt>
                                <dd>
                                  {optionalText(detailWaiverEvidence.reason)}
                                </dd>
                              </div>
                              <div>
                                <dt>Expires</dt>
                                <dd>
                                  {optionalText(detailWaiverEvidence.expiresOn)}
                                </dd>
                              </div>
                              <div>
                                <dt>Review</dt>
                                <dd>
                                  {optionalText(detailWaiverEvidence.reviewOn)}
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
                          </section>
                        ) : null}

                        <section
                          className="why-priority-panel"
                          aria-label="Why this priority"
                        >
                          <div className="detail-section-heading">
                            <h3>Why this priority</h3>
                            <span>
                              Score{" "}
                              {formatNullableNumber(findingDetail.risk_score)}
                            </span>
                          </div>
                          <p>
                            {findingWhyText(findingDetail, findingExplanation)}
                          </p>
                          <div className="recommendation-callout">
                            <span>Recommended action</span>
                            <strong>
                              {findingRecommendedAction(
                                findingDetail,
                                findingExplanation,
                              )}
                            </strong>
                          </div>
                          {detailReasonRows.length > 0 ? (
                            <dl
                              className="reason-list"
                              aria-label="Matched reasons"
                            >
                              {detailReasonRows.map((reason) => (
                                <div key={`${reason.label}:${reason.detail}`}>
                                  <dt>{labelize(reason.label)}</dt>
                                  <dd>{reason.detail}</dd>
                                </div>
                              ))}
                            </dl>
                          ) : null}
                        </section>

                        <section
                          className="occurrences-panel"
                          aria-label="Occurrences"
                        >
                          <div className="detail-section-heading">
                            <h3>Occurrences</h3>
                            <span>
                              {detailOccurrences.length} source row(s)
                            </span>
                          </div>
                          {detailOccurrences.length > 0 ? (
                            <div className="table-wrap occurrences-table-wrap">
                              <table aria-label="Occurrences table">
                                <thead>
                                  <tr>
                                    <th>Source</th>
                                    <th>Component</th>
                                    <th>Asset</th>
                                    <th>Owner</th>
                                    <th>Severity</th>
                                    <th>Fix</th>
                                    <th>VEX</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {detailOccurrences.map(
                                    (occurrence, index) => {
                                      const fixVersions =
                                        Array.isArray(
                                          occurrence.fix_versions,
                                        ) && occurrence.fix_versions.length > 0
                                          ? occurrence.fix_versions.join(", ")
                                          : stringValue(occurrence.fix_version)
                                      return (
                                        <tr
                                          key={
                                            stringValue(occurrence.id) ??
                                            `occurrence-${index + 1}`
                                          }
                                        >
                                          <td>
                                            <span className="finding-primary">
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
                                          </td>
                                          <td>
                                            <span className="finding-primary">
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
                                                stringValue(occurrence.purl),
                                              )}
                                            </small>
                                          </td>
                                          <td>
                                            <span className="finding-primary">
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
                                                  occurrence.target_kind,
                                                ),
                                                labelize(
                                                  stringValue(
                                                    occurrence.asset_exposure,
                                                  ),
                                                ),
                                              ])}
                                            </small>
                                          </td>
                                          <td>
                                            <span className="finding-primary">
                                              {optionalText(
                                                stringValue(
                                                  occurrence.asset_owner,
                                                ),
                                              )}
                                            </span>
                                            <small>
                                              {optionalText(
                                                stringValue(
                                                  occurrence.asset_business_service,
                                                ),
                                              )}
                                            </small>
                                          </td>
                                          <td>
                                            {optionalText(
                                              stringValue(
                                                occurrence.raw_severity,
                                              ),
                                            )}
                                          </td>
                                          <td>{optionalText(fixVersions)}</td>
                                          <td>
                                            <span className="finding-primary">
                                              {optionalText(
                                                labelize(
                                                  stringValue(
                                                    occurrence.vex_status,
                                                  ),
                                                ),
                                              )}
                                            </span>
                                            <small>
                                              {optionalText(
                                                joinedValues([
                                                  stringValue(
                                                    occurrence.vex_justification,
                                                  ),
                                                  stringValue(
                                                    occurrence.vex_action_statement,
                                                  ),
                                                  stringValue(
                                                    occurrence.vex_match_type,
                                                  ),
                                                ]),
                                              )}
                                            </small>
                                          </td>
                                        </tr>
                                      )
                                    },
                                  )}
                                </tbody>
                              </table>
                            </div>
                          ) : (
                            <p className="detail-empty">
                              No source occurrences have been recorded for this
                              finding.
                            </p>
                          )}
                        </section>

                        <section
                          className="data-quality-panel"
                          aria-label="Data Quality Flags"
                        >
                          <div className="detail-section-heading">
                            <h3>Data Quality Flags</h3>
                            <span>
                              Confidence{" "}
                              {findingExplanation?.data_quality_confidence ??
                                stringValue(
                                  objectRecord(findingDetail.data_quality_json)
                                    .confidence,
                                ) ??
                                "high"}
                            </span>
                          </div>
                          {detailDataQualityRows.length > 0 ? (
                            <ul className="data-quality-list">
                              {detailDataQualityRows.map((flag) => (
                                <li key={flag.key}>
                                  <strong>{labelize(flag.code)}</strong>
                                  <span>
                                    {flag.source} / {labelize(flag.severity)}
                                  </span>
                                  <p>{flag.message}</p>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="detail-empty">
                              No data quality flags recorded.
                            </p>
                          )}
                          <section
                            className="provider-gap-list"
                            aria-label="Provider data coverage"
                          >
                            <span>Provider data coverage</span>
                            {detailProviderGaps.length > 0 ? (
                              <ul>
                                {detailProviderGaps.map((gap) => (
                                  <li key={gap}>{gap}</li>
                                ))}
                              </ul>
                            ) : (
                              <p>No provider gaps for this finding.</p>
                            )}
                          </section>
                        </section>
                      </div>
                    ) : (
                      <section
                        className="ttp-context-panel"
                        id="finding-ttp-panel"
                        role="tabpanel"
                        aria-labelledby="finding-ttp-tab"
                        aria-label="TTP Context"
                      >
                        <div className="detail-section-heading">
                          <h3>ATT&amp;CK threat context</h3>
                          <span>
                            {detailAttackContext?.mapped
                              ? "Mapped context"
                              : "No approved mapping"}
                          </span>
                        </div>
                        {detailAttackEmpty ? (
                          <section
                            className="ttp-empty-state"
                            aria-label="TTP context empty state"
                          >
                            <strong>
                              No approved ATT&amp;CK mapping is stored for this
                              finding.
                            </strong>
                            <p>
                              Workbench does not infer tactics or techniques for
                              unmapped CVEs. Add a reviewed CTID or local
                              curated mapping before using ATT&amp;CK context in
                              queue decisions.
                            </p>
                          </section>
                        ) : (
                          <>
                            <section
                              className="ttp-summary-grid"
                              aria-label="TTP context summary"
                            >
                              <article>
                                <span>Source</span>
                                <strong>
                                  {detailAttackContext?.source ?? "none"}
                                </strong>
                              </article>
                              <article>
                                <span>Confidence</span>
                                <strong
                                  className={`ttp-confidence ${
                                    detailAttackContext?.confidence ?? "unknown"
                                  }`}
                                >
                                  {attackConfidenceLabel(
                                    detailAttackContext?.confidence,
                                  )}
                                </strong>
                                {detailAttackContext?.low_confidence ? (
                                  <small>
                                    Review required before using this context
                                    for queue decisions.
                                  </small>
                                ) : null}
                              </article>
                              <article>
                                <span>Review</span>
                                <strong>
                                  {attackReviewLabel(
                                    detailAttackContext?.review_status,
                                  )}
                                </strong>
                              </article>
                              <article>
                                <span>Relevance</span>
                                <strong>
                                  {detailAttackContext?.attack_relevance ??
                                    "Mapped"}
                                </strong>
                              </article>
                            </section>

                            <div className="table-wrap ttp-table-wrap">
                              <table aria-label="TTP Context techniques">
                                <thead>
                                  <tr>
                                    <th>Technique</th>
                                    <th>Tactics</th>
                                    <th>Confidence</th>
                                    <th>Review</th>
                                    <th>Rationale</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {detailAttackTechniques.map((technique) => (
                                    <tr key={technique.technique_id}>
                                      <td>
                                        <span className="finding-primary">
                                          {technique.technique_id}
                                        </span>
                                        <small>
                                          {optionalText(technique.name)}
                                        </small>
                                      </td>
                                      <td>
                                        {attackTacticsLabel(technique.tactics)}
                                      </td>
                                      <td>
                                        <span
                                          className={`ttp-confidence ${
                                            technique.confidence ?? "unknown"
                                          }`}
                                        >
                                          {attackConfidenceLabel(
                                            technique.confidence,
                                          )}
                                        </span>
                                      </td>
                                      <td>
                                        {attackReviewLabel(
                                          technique.review_status,
                                        )}
                                      </td>
                                      <td>
                                        {optionalText(technique.rationale)}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </>
                        )}
                        <section
                          className="ttp-detection-placeholder"
                          aria-label="Detection coverage"
                        >
                          <span>Detection coverage</span>
                          <p>
                            Coverage controls are not connected to this finding
                            yet. Use this placeholder to record future detection
                            and mitigation evidence.
                          </p>
                        </section>
                        <p className="ttp-safety-note">
                          Defensive context only: this tab does not provide
                          exploit steps, payloads, PoC guidance, active probing,
                          or offensive procedure instructions.
                        </p>
                      </section>
                    )}
                  </>
                ) : null}
              </section>
            ) : isFindingsList ? (
              <section
                className="findings-workflow"
                aria-label="Findings table workflow"
              >
                <section
                  className="findings-controls"
                  aria-label="Findings filters"
                >
                  <label>
                    <span>Project</span>
                    <select
                      aria-label="Findings project"
                      disabled={projectListLoading || projects.length === 0}
                      onChange={(event) => {
                        setFindingOffset(0)
                        setSelectedProjectId(event.target.value)
                      }}
                      value={selectedProjectId}
                    >
                      {projects.length === 0 ? (
                        <option value="">No projects</option>
                      ) : null}
                      {projects.map((project) => (
                        <option key={project.id} value={project.id}>
                          {project.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  {findingAssetId ? (
                    <section
                      className="project-context"
                      aria-label="Asset finding filter"
                    >
                      <span>Asset filter</span>
                      <strong>{findingAssetKey ?? findingAssetId}</strong>
                      <button
                        className="secondary-action"
                        onClick={() => clearFindingFilters()}
                        type="button"
                      >
                        Clear Asset
                      </button>
                    </section>
                  ) : null}
                  <label>
                    <span>Priority</span>
                    <select
                      aria-label="Priority filter"
                      onChange={(event) =>
                        updateFindingFilter(
                          "priority",
                          event.target.value as FindingFilters["priority"],
                        )
                      }
                      value={findingFilters.priority}
                    >
                      <option value="">Any priority</option>
                      {findingPriorityOptions.map((priority) => (
                        <option key={priority} value={priority}>
                          {labelize(priority)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Status</span>
                    <select
                      aria-label="Status filter"
                      onChange={(event) =>
                        updateFindingFilter(
                          "status",
                          event.target.value as FindingFilters["status"],
                        )
                      }
                      value={findingFilters.status}
                    >
                      <option value="">Any status</option>
                      {findingStatusOptions.map((status) => (
                        <option key={status} value={status}>
                          {labelize(status)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>KEV</span>
                    <select
                      aria-label="KEV filter"
                      onChange={(event) =>
                        updateFindingFilter(
                          "kev",
                          event.target.value as KevFilter,
                        )
                      }
                      value={findingFilters.kev}
                    >
                      <option value="">Any KEV</option>
                      <option value="true">KEV only</option>
                      <option value="false">Not KEV</option>
                    </select>
                  </label>
                  <label>
                    <span>Owner or service</span>
                    <input
                      aria-label="Owner service filter"
                      onChange={(event) =>
                        updateFindingFilter("ownerService", event.target.value)
                      }
                      placeholder="platform or payments"
                      value={findingFilters.ownerService}
                    />
                  </label>
                  <label>
                    <span>Exposure</span>
                    <select
                      aria-label="Exposure filter"
                      onChange={(event) =>
                        updateFindingFilter(
                          "exposure",
                          event.target.value as FindingFilters["exposure"],
                        )
                      }
                      value={findingFilters.exposure}
                    >
                      <option value="">Any exposure</option>
                      {findingExposureOptions.map((exposure) => (
                        <option key={exposure} value={exposure}>
                          {labelize(exposure)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>EPSS min</span>
                    <input
                      aria-label="EPSS min filter"
                      inputMode="decimal"
                      max="1"
                      min="0"
                      onChange={(event) =>
                        updateFindingFilter("epssMin", event.target.value)
                      }
                      placeholder="0.40"
                      step="0.01"
                      type="number"
                      value={findingFilters.epssMin}
                    />
                  </label>
                  <label>
                    <span>EPSS max</span>
                    <input
                      aria-label="EPSS max filter"
                      inputMode="decimal"
                      max="1"
                      min="0"
                      onChange={(event) =>
                        updateFindingFilter("epssMax", event.target.value)
                      }
                      placeholder="0.95"
                      step="0.01"
                      type="number"
                      value={findingFilters.epssMax}
                    />
                  </label>
                  <label>
                    <span>CVSS min</span>
                    <input
                      aria-label="CVSS min filter"
                      inputMode="decimal"
                      max="10"
                      min="0"
                      onChange={(event) =>
                        updateFindingFilter("cvssMin", event.target.value)
                      }
                      placeholder="7.0"
                      step="0.1"
                      type="number"
                      value={findingFilters.cvssMin}
                    />
                  </label>
                  <label>
                    <span>CVSS max</span>
                    <input
                      aria-label="CVSS max filter"
                      inputMode="decimal"
                      max="10"
                      min="0"
                      onChange={(event) =>
                        updateFindingFilter("cvssMax", event.target.value)
                      }
                      placeholder="10.0"
                      step="0.1"
                      type="number"
                      value={findingFilters.cvssMax}
                    />
                  </label>
                  <button
                    className="secondary-action"
                    disabled={!activeFindingFilters}
                    onClick={clearFindingFilters}
                    type="button"
                  >
                    Clear Filters
                  </button>
                </section>

                <section
                  className="findings-sortbar"
                  aria-label="Findings sorting"
                >
                  <label>
                    <span>Sort</span>
                    <select
                      aria-label="Sort findings"
                      onChange={(event) =>
                        updateFindingSort(event.target.value as FindingsSort)
                      }
                      value={findingSort}
                    >
                      {findingSortOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Direction</span>
                    <select
                      aria-label="Sort direction"
                      onChange={(event) =>
                        updateFindingDirection(
                          event.target.value as FindingsDirection,
                        )
                      }
                      value={findingDirection}
                    >
                      <option value="asc">Ascending</option>
                      <option value="desc">Descending</option>
                    </select>
                  </label>
                  <label>
                    <span>Page size</span>
                    <select
                      aria-label="Findings page size"
                      onChange={(event) =>
                        updateFindingPageSize(Number(event.target.value))
                      }
                      value={findingPageSize}
                    >
                      {findingPageSizes.map((size) => (
                        <option key={size} value={size}>
                          {size}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="findings-page-summary" aria-live="polite">
                    <span>Showing</span>
                    <strong>
                      {findingPageStart}-{findingPageEnd} of {findingCount}
                    </strong>
                  </div>
                  <div className="findings-page-actions">
                    <button
                      className="secondary-action"
                      disabled={findingsLoading || findingOffset === 0}
                      onClick={() =>
                        setFindingOffset((offset) =>
                          Math.max(0, offset - findingPageSize),
                        )
                      }
                      type="button"
                    >
                      Previous
                    </button>
                    <button
                      className="secondary-action"
                      disabled={
                        findingsLoading ||
                        findingOffset + findingPageSize >= findingCount
                      }
                      onClick={() =>
                        setFindingOffset((offset) => offset + findingPageSize)
                      }
                      type="button"
                    >
                      Next
                    </button>
                  </div>
                </section>

                {findingsError ? (
                  <p className="dashboard-alert" role="alert">
                    {findingsError}
                  </p>
                ) : null}
                {findingsLoading ? (
                  <p className="dashboard-state" role="status">
                    Loading findings
                  </p>
                ) : null}

                {!findingsLoading && !findingsError && projects.length === 0 ? (
                  <section
                    className="dashboard-empty"
                    aria-label="Findings no project empty state"
                  >
                    <h3>No projects yet</h3>
                    <p>Create a project before reviewing findings.</p>
                    <Link className="primary-action" to="/projects">
                      Projects
                    </Link>
                  </section>
                ) : null}

                {!findingsLoading &&
                !findingsError &&
                selectedProject &&
                findings.length === 0 &&
                !activeFindingFilters ? (
                  <section
                    className="dashboard-empty"
                    aria-label="Findings empty state"
                  >
                    <h3>No findings in {selectedProject.name}</h3>
                    <p>
                      Import scanner, SBOM, or CVE-list data to create findings.
                    </p>
                    <Link className="primary-action" to="/imports">
                      Imports
                    </Link>
                  </section>
                ) : null}

                {!findingsLoading &&
                !findingsError &&
                selectedProject &&
                findings.length === 0 &&
                activeFindingFilters ? (
                  <section
                    className="dashboard-empty"
                    aria-label="Findings filter empty state"
                  >
                    <h3>No findings match these filters</h3>
                    <p>
                      Clear or adjust filters to broaden the server-side query.
                    </p>
                    <button
                      className="secondary-action"
                      onClick={clearFindingFilters}
                      type="button"
                    >
                      Clear Filters
                    </button>
                  </section>
                ) : null}

                {findings.length > 0 ? (
                  <div className="table-wrap findings-table-wrap">
                    <table aria-label="Findings table">
                      <thead>
                        <tr>
                          <th>Priority</th>
                          <th>Score</th>
                          <th>CVE</th>
                          <th>Component</th>
                          <th>Asset</th>
                          <th>Owner</th>
                          <th>EPSS</th>
                          <th>CVSS</th>
                          <th>KEV</th>
                          <th>Status</th>
                          <th>Last Seen</th>
                        </tr>
                      </thead>
                      <tbody>
                        {findings.map((finding) => (
                          <tr
                            className={`finding-row tone-${findingPriorityTone(
                              finding,
                            )}`}
                            key={finding.id}
                          >
                            <td>
                              <span
                                className={`severity ${
                                  finding.priority ?? "low"
                                }`}
                              >
                                {labelize(finding.priority)}
                              </span>
                            </td>
                            <td>{formatNullableNumber(finding.risk_score)}</td>
                            <td>
                              <Link
                                className="finding-cve-link"
                                params={{ findingId: finding.id }}
                                to="/findings/$findingId"
                              >
                                {finding.cve_id}
                              </Link>
                            </td>
                            <td>
                              <span className="finding-primary">
                                {findingComponentLabel(finding)}
                              </span>
                              <small>
                                {optionalText(finding.component_purl)}
                              </small>
                            </td>
                            <td>
                              <span className="finding-primary">
                                {findingAssetLabel(finding)}
                              </span>
                              <small>{labelize(finding.exposure)}</small>
                            </td>
                            <td>
                              <span className="finding-primary">
                                {optionalText(finding.owner)}
                              </span>
                              <small>
                                {optionalText(finding.business_service)}
                              </small>
                            </td>
                            <td>{formatEpss(finding.epss)}</td>
                            <td>
                              {formatNullableNumber(finding.cvss_base_score)}
                            </td>
                            <td>
                              <span
                                className={
                                  finding.in_kev
                                    ? "kev-pill matched"
                                    : "kev-pill"
                                }
                              >
                                {finding.in_kev ? "Yes" : "No"}
                              </span>
                            </td>
                            <td>{labelize(finding.status)}</td>
                            <td>{formatDateTime(finding.last_seen_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </section>
            ) : currentPath === "/providers" ? (
              <section
                className="providers-workflow"
                aria-label="Provider Status page"
              >
                {providerStatusError ? (
                  <p className="dashboard-alert" role="alert">
                    {providerStatusError}
                  </p>
                ) : null}
                {providerStatusLoading ? (
                  <p className="dashboard-state" role="status">
                    Loading provider status
                  </p>
                ) : null}

                <section
                  className="provider-summary-grid"
                  aria-label="Provider status summary"
                >
                  <article className="provider-summary-card">
                    <span>Status</span>
                    <strong>{providerStatus?.status ?? "loading"}</strong>
                    <small>
                      {providerStatus?.last_error ??
                        providerStatus?.warnings?.[0] ??
                        "Latest provider evidence is usable."}
                    </small>
                  </article>
                  <article className="provider-summary-card">
                    <span>Snapshot mode</span>
                    <strong>
                      {providerStatus?.snapshot_mode ?? "missing"}
                    </strong>
                    <small>
                      {providerStatus?.snapshot.locked_provider_data
                        ? "Locked replay evidence"
                        : "Stored provider evidence"}
                    </small>
                  </article>
                  <article className="provider-summary-card">
                    <span>Last sync</span>
                    <strong>{providerStatus?.last_sync ?? "N.A."}</strong>
                    <small>
                      Cache age{" "}
                      {formatCacheAge(providerStatus?.cache_age_seconds)}
                    </small>
                  </article>
                  <article className="provider-summary-card">
                    <span>Snapshot ID</span>
                    <strong>{providerSnapshotId(providerStatus)}</strong>
                    <small>
                      {providerStatus?.snapshot.content_hash ??
                        "No content hash recorded"}
                    </small>
                  </article>
                </section>

                <section
                  className="provider-card-grid"
                  aria-label="Provider cards"
                >
                  {(providerStatus?.sources ?? fallbackProviderSources).map(
                    (source) => (
                      <article
                        aria-label={`${providerSourceLabel(source)} provider card`}
                        className={`provider-card ${providerSourceState(source)}`}
                        key={source.name}
                        title={providerSourceDetail(source)}
                      >
                        <div className="provider-card-header">
                          <div>
                            <span>Provider</span>
                            <h3>{providerSourceLabel(source)}</h3>
                          </div>
                          <span
                            className={`source-pill ${providerSourceState(source)}`}
                          >
                            {providerSourceState(source)}
                          </span>
                        </div>
                        <dl className="provider-card-facts">
                          <div>
                            <dt>Selected</dt>
                            <dd>{source.selected ? "Yes" : "No"}</dd>
                          </div>
                          <div>
                            <dt>Value</dt>
                            <dd>{source.value ?? "N.A."}</dd>
                          </div>
                          <div>
                            <dt>Last sync</dt>
                            <dd>{source.last_sync ?? "N.A."}</dd>
                          </div>
                          <div>
                            <dt>Cache age</dt>
                            <dd>{formatCacheAge(source.cache_age_seconds)}</dd>
                          </div>
                        </dl>
                        <p>{providerSourceDetail(source)}</p>
                      </article>
                    ),
                  )}
                </section>

                <section
                  className="provider-snapshot-panel"
                  aria-label="Provider snapshot evidence"
                >
                  <div className="detail-section-heading">
                    <h3>Provider Snapshot</h3>
                    <span>{providerStatus?.snapshot.mode ?? "missing"}</span>
                  </div>
                  <dl className="project-meta">
                    <div>
                      <dt>Snapshot ID</dt>
                      <dd>{providerSnapshotId(providerStatus)}</dd>
                    </div>
                    <div>
                      <dt>Content hash</dt>
                      <dd>
                        {providerStatus?.snapshot.content_hash ??
                          "No content hash recorded"}
                      </dd>
                    </div>
                    <div>
                      <dt>Generated</dt>
                      <dd>
                        {providerStatus?.snapshot.generated_at ??
                          providerStatus?.snapshot.created_at ??
                          "N.A."}
                      </dd>
                    </div>
                    <div>
                      <dt>Requested CVEs</dt>
                      <dd>{providerStatus?.snapshot.requested_cves ?? 0}</dd>
                    </div>
                    <div>
                      <dt>Selected sources</dt>
                      <dd>{providerSelectedSources(providerStatus)}</dd>
                    </div>
                    <div>
                      <dt>Source path</dt>
                      <dd>{providerStatus?.snapshot.source_path ?? "N.A."}</dd>
                    </div>
                    <div>
                      <dt>Cache dir</dt>
                      <dd>{providerStatus?.cache_dir ?? "N.A."}</dd>
                    </div>
                    <div>
                      <dt>Snapshot dir</dt>
                      <dd>{providerStatus?.snapshot_dir ?? "N.A."}</dd>
                    </div>
                    <div>
                      <dt>Source hashes</dt>
                      <dd>{providerSourceHashes(providerStatus)}</dd>
                    </div>
                  </dl>
                </section>

                <section
                  className="provider-quality-panel"
                  aria-label="Provider data quality"
                >
                  <div className="detail-section-heading">
                    <h3>Data Quality</h3>
                    <span>Provider freshness and degraded evidence</span>
                  </div>
                  <ul className="data-quality-list">
                    {providerDataQualityNotes(providerStatus).map((note) => (
                      <li key={note}>
                        <strong>Provider evidence</strong>
                        <span>Data quality note</span>
                        <p>{note}</p>
                      </li>
                    ))}
                    {(providerStatus?.warnings ?? []).map((warning) => (
                      <li key={warning}>
                        <strong>Warning</strong>
                        <span>Degraded evidence</span>
                        <p>{warning}</p>
                      </li>
                    ))}
                    {providerStatus?.last_error ? (
                      <li>
                        <strong>Last Error</strong>
                        <span>Provider update failure</span>
                        <p>{providerStatus.last_error}</p>
                      </li>
                    ) : null}
                  </ul>
                </section>

                <section
                  className="provider-snapshot-panel"
                  aria-label="Latest provider update job"
                >
                  <div className="detail-section-heading">
                    <h3>Latest Update Job</h3>
                    <span>
                      {providerStatus?.latest_update_job?.status ?? "none"}
                    </span>
                  </div>
                  {providerStatus?.latest_update_job ? (
                    <dl className="project-meta">
                      <div>
                        <dt>Job ID</dt>
                        <dd>{providerStatus.latest_update_job.id}</dd>
                      </div>
                      <div>
                        <dt>Status</dt>
                        <dd>{providerStatus.latest_update_job.status}</dd>
                      </div>
                      <div>
                        <dt>Requested sources</dt>
                        <dd>
                          {providerStatus.latest_update_job.requested_sources?.join(
                            ", ",
                          ) ?? "N.A."}
                        </dd>
                      </div>
                      <div>
                        <dt>Started</dt>
                        <dd>
                          {providerStatus.latest_update_job.started_at ??
                            "N.A."}
                        </dd>
                      </div>
                      <div>
                        <dt>Finished</dt>
                        <dd>
                          {providerStatus.latest_update_job.finished_at ??
                            "N.A."}
                        </dd>
                      </div>
                      <div>
                        <dt>Error</dt>
                        <dd>
                          {providerStatus.latest_update_job.error_message ??
                            "None"}
                        </dd>
                      </div>
                    </dl>
                  ) : (
                    <p className="detail-empty">
                      No provider update job has been recorded.
                    </p>
                  )}
                </section>
              </section>
            ) : currentPath === "/reports" ? (
              <section
                className="reports-workflow"
                aria-label="Reports workspace"
              >
                <section
                  className="reports-readiness-panel"
                  aria-label="Reports readiness"
                >
                  <div>
                    <span>Report generation</span>
                    <h3>Generate and download reports for the selected run</h3>
                    <p>
                      Create Markdown, HTML, JSON, CSV, ATT&CK Navigator, and
                      evidence ZIP artifacts from completed template analysis
                      runs. History rows stay linked to backend downloads and
                      checksum-backed metadata.
                    </p>
                  </div>
                  <dl className="report-readiness-facts">
                    <div>
                      <dt>Project</dt>
                      <dd>{selectedProject?.name ?? "No project selected"}</dd>
                    </div>
                    <div>
                      <dt>Run</dt>
                      <dd>
                        {selectedReportRun
                          ? `${runStatusLabel(selectedReportRun.status)} / ${runFileLabel(selectedReportRun)}`
                          : runsLoading
                            ? "Loading runs"
                            : "No reportable run"}
                      </dd>
                    </div>
                    <div>
                      <dt>Findings</dt>
                      <dd>
                        {selectedRunSummary?.finding_count ??
                          projectSummary?.finding_count ??
                          0}
                      </dd>
                    </div>
                    <div>
                      <dt>Activation</dt>
                      <dd>
                        {reportActionsEnabled
                          ? "Ready"
                          : "Select completed run"}
                      </dd>
                    </div>
                  </dl>
                </section>

                <section
                  className="report-run-panel"
                  aria-label="Report run selection"
                >
                  <label>
                    <span>Analysis run</span>
                    <select
                      aria-label="Report analysis run"
                      disabled={runsLoading || projectRuns.length === 0}
                      onChange={(event) => setSelectedRunId(event.target.value)}
                      value={selectedRunId}
                    >
                      {projectRuns.length === 0 ? (
                        <option value="">No runs available</option>
                      ) : null}
                      {projectRuns.map((run) => (
                        <option key={run.id} value={run.id}>
                          {`${runStatusLabel(run.status)} - ${runFileLabel(run)} - ${run.id.slice(0, 8)}`}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div>
                    <span>Report history</span>
                    <strong>
                      {reportsLoading
                        ? "Loading"
                        : `${reports.length} artifacts`}
                    </strong>
                  </div>
                  <div>
                    <span>Latest status</span>
                    <strong>
                      {selectedReportRun
                        ? runStatusLabel(selectedReportRun.status)
                        : "N.A."}
                    </strong>
                  </div>
                </section>

                {runsError ? (
                  <p className="dashboard-alert" role="alert">
                    {runsError}
                  </p>
                ) : null}
                {runDetailError ? (
                  <p className="dashboard-alert" role="alert">
                    {runDetailError}
                  </p>
                ) : null}
                {reportsError ? (
                  <p className="dashboard-alert" role="alert">
                    {reportsError}
                  </p>
                ) : null}
                {reportActionError ? (
                  <p className="dashboard-alert" role="alert">
                    {reportActionError}
                  </p>
                ) : null}
                {reportActionMessage ? (
                  <p className="dashboard-success" role="status">
                    {reportActionMessage}
                  </p>
                ) : null}

                <section
                  className="report-card-grid"
                  aria-label="Report export cards"
                >
                  {reportActionCards.map((card) => (
                    <article className="report-action-card" key={card.title}>
                      <div className="report-card-header">
                        <card.icon aria-hidden="true" size={22} />
                        <div>
                          <span>{card.format}</span>
                          <h3>{card.title}</h3>
                        </div>
                      </div>
                      <p>{card.detail}</p>
                      <div className="report-card-footer">
                        <span className="report-stage-pill">{card.stage}</span>
                        <button
                          className="report-placeholder-button"
                          disabled={
                            !reportActionsEnabled ||
                            activeReportFormat === card.reportFormat
                          }
                          onClick={() => void createReport(card.reportFormat)}
                          type="button"
                        >
                          <Download aria-hidden="true" size={16} />
                          <span>
                            {activeReportFormat === card.reportFormat
                              ? "Generating"
                              : card.actionLabel}
                          </span>
                        </button>
                      </div>
                    </article>
                  ))}
                </section>

                <section
                  className="report-history-panel"
                  aria-label="Reports history"
                >
                  <div className="detail-section-heading">
                    <div>
                      <h3>Report History</h3>
                      <span>Prepared artifact list</span>
                    </div>
                    <History aria-hidden="true" size={20} />
                  </div>
                  <ul
                    className="report-history-list"
                    aria-label="Report history list"
                  >
                    <li className="report-history-row heading">
                      <span>Artifact</span>
                      <span>Format</span>
                      <span>Status</span>
                      <span>Download</span>
                    </li>
                    {reports.length === 0 ? (
                      <li className="report-history-row empty">
                        <span>No generated reports yet</span>
                        <span>
                          Markdown / HTML / JSON / CSV / Navigator / ZIP
                        </span>
                        <span>
                          {reportsLoading ? "Loading" : "Ready for VPW-053"}
                        </span>
                        <span>Generate first</span>
                      </li>
                    ) : (
                      reports.map((report) => (
                        <li className="report-history-row" key={report.id}>
                          <span>
                            <strong>{report.filename}</strong>
                            <small>
                              {report.sha256.slice(0, 12)} /{" "}
                              {reportSizeLabel(report.size_bytes)}
                            </small>
                          </span>
                          <span>{reportFormatLabel(report.format)}</span>
                          <span>{formatDateTime(report.created_at)}</span>
                          <span className="report-history-actions">
                            {report.format === "zip" ? (
                              <button
                                className="icon-button"
                                type="button"
                                aria-label={`Verify ${report.filename}`}
                                onClick={() =>
                                  void verifyEvidenceReport(report)
                                }
                              >
                                <ShieldCheck aria-hidden="true" size={16} />
                              </button>
                            ) : null}
                            <button
                              className="report-download-button"
                              type="button"
                              aria-label={`Download ${report.filename}`}
                              onClick={() => void downloadReport(report)}
                            >
                              <Download aria-hidden="true" size={16} />
                              <span>Download</span>
                            </button>
                          </span>
                        </li>
                      ))
                    )}
                  </ul>
                </section>
              </section>
            ) : (
              <div className="dashboard-panel-body">
                {dashboardError ? (
                  <p className="dashboard-alert" role="alert">
                    {dashboardError}
                  </p>
                ) : null}

                {dashboardLoading ? (
                  <p className="dashboard-state" role="status">
                    Loading dashboard summary
                  </p>
                ) : null}

                {!dashboardLoading &&
                !dashboardError &&
                projects.length === 0 ? (
                  <section
                    className="dashboard-empty"
                    aria-label="Dashboard empty state"
                  >
                    <h3>No projects yet</h3>
                    <p>
                      Create a project or import a CVE list to populate the
                      dashboard.
                    </p>
                    <div className="empty-actions">
                      <Link className="primary-action" to="/projects">
                        Projects
                      </Link>
                      <Link className="secondary-action" to="/imports">
                        Imports
                      </Link>
                    </div>
                  </section>
                ) : null}

                {!dashboardLoading &&
                !dashboardError &&
                selectedProject &&
                projectSummary !== null &&
                (projectSummary.finding_count ?? 0) === 0 ? (
                  <section
                    className="dashboard-empty"
                    aria-label="No findings empty state"
                  >
                    <h3>No findings in {selectedProject.name}</h3>
                    <p>
                      Import scanner, SBOM, or CVE-list data to create findings.
                    </p>
                    <div className="empty-actions">
                      <Link className="primary-action" to="/imports">
                        Imports
                      </Link>
                      <Link className="secondary-action" to="/projects">
                        Projects
                      </Link>
                    </div>
                  </section>
                ) : null}

                {!dashboardLoading &&
                !dashboardError &&
                projectSummary !== null &&
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
                  <p className="dashboard-alert" role="alert">
                    {governanceError}
                  </p>
                ) : null}

                {governanceLoading ? (
                  <p className="dashboard-state" role="status">
                    Loading governance rollups
                  </p>
                ) : null}

                {!governanceLoading &&
                !governanceError &&
                selectedProject &&
                projectGovernanceRollups ? (
                  <section
                    className="governance-summary-widget"
                    aria-label="Top Services by Risk"
                  >
                    <div className="detail-section-heading">
                      <h3>Top Services by Risk</h3>
                      <span>Owner, service, and waiver debt concentration</span>
                    </div>
                    {topServiceRows.length === 0 ? (
                      <p className="attack-summary-empty">
                        No service rollups are available for this project.
                      </p>
                    ) : (
                      <ul className="governance-service-list">
                        {topServiceRows.map((service) => (
                          <li key={service.label}>
                            <div>
                              <strong>{service.label}</strong>
                              <span>
                                {service.finding_count ?? 0} finding
                                {service.finding_count === 1 ? "" : "s"}
                              </span>
                            </div>
                            <small>
                              Critical {service.critical_count ?? 0} / High{" "}
                              {service.high_count ?? 0} / Score{" "}
                              {formatRollupScore(service.risk_score_total)} /
                              Waiver debt {serviceWaiverDebtCount(service)}
                            </small>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>
                ) : null}
              </div>
            )}
          </div>

          <div className="side-panel">
            <section
              className="provider-status-section"
              aria-label="Provider Status"
            >
              <div className="panel-header compact inline-header">
                <div>
                  <h2>Provider Status</h2>
                  <span>
                    {providerStatus?.snapshot.content_hash ??
                      "No snapshot recorded"}
                  </span>
                </div>
                <Database aria-hidden="true" size={18} />
              </div>

              <div
                className={`provider-state ${
                  providerStatus?.status === "ok" ? "ok" : "degraded"
                }`}
              >
                <span>{providerStatus?.status ?? "loading"}</span>
                <strong>{providerStatus?.snapshot_mode ?? "missing"}</strong>
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
                  <dd>{formatCacheAge(providerStatus?.cache_age_seconds)}</dd>
                </div>
                <div>
                  <dt>Last error</dt>
                  <dd>
                    {providerStatus?.last_error ?? (statusError || "None")}
                  </dd>
                </div>
              </dl>

              <ul className="provider-sources" aria-label="Provider sources">
                {(providerStatus?.sources ?? fallbackProviderSources).map(
                  (source) => (
                    <li className="provider-source" key={source.name}>
                      <div>
                        <strong>{source.name.toUpperCase()}</strong>
                        <span>{source.value ?? "N.A."}</span>
                      </div>
                      <span
                        className={
                          source.available
                            ? "source-pill available"
                            : "source-pill"
                        }
                      >
                        {source.available ? "available" : "missing"}
                      </span>
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
                <p className="dashboard-alert" role="alert">
                  {attackSummaryError}
                </p>
              ) : null}

              {attackSummaryLoading ? (
                <p className="dashboard-state" role="status">
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
                  No reviewed ATT&CK technique mappings are stored for this
                  project.
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
                          <span>{technique.name ?? "Unnamed technique"}</span>
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
        </section>
      </main>
    </div>
  )
}

const fallbackProviderSources: ProviderSourceStatusPublic[] = [
  { name: "nvd", available: false, value: null },
  { name: "epss", available: false, value: null },
  { name: "kev", available: false, value: null },
]

function formatCacheAge(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) {
    return "N.A."
  }
  if (seconds < 60) {
    return `${seconds}s`
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m`
  }
  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)}h`
  }
  return `${Math.floor(seconds / 86400)}d`
}
