import { Link, useLocation, useNavigate } from "@tanstack/react-router"
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Database,
  FileArchive,
  FileInput,
  FolderKanban,
  Gauge,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Settings,
  ShieldCheck,
} from "lucide-react"
import { type FormEvent, useEffect, useState } from "react"
import { clearAccessToken } from "./auth"
import {
  type AnalysisRunPublic,
  type AnalysisRunSummaryPublic,
  ApiError,
  type AssetExposure,
  type FindingPriority,
  type FindingPublic,
  type FindingStatus,
  type FindingsReadProjectFindingsData,
  FindingsService,
  type ImportParseErrorPublic,
  ImportsService,
  type ProjectDecisionSummaryPublic,
  type ProjectPublic,
  ProjectsService,
  type ProviderStatusPublic,
  ProvidersService,
  RunsService,
  type UserPublic,
  UsersService,
  WorkbenchService,
  type WorkbenchStatus,
} from "./client"

const workbenchNavigation = [
  { label: "Dashboard", icon: LayoutDashboard, to: "/" },
  { label: "Projects", icon: FolderKanban, to: "/projects" },
  { label: "Imports", icon: FileInput, to: "/imports" },
  { label: "Findings", icon: ListChecks, to: "/findings" },
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
  return normalized in routeDetails ? (normalized as WorkbenchPath) : "/"
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

type ImportWizardState = {
  file: File | null
  inputType: ImportFormat
}

const defaultImportWizardState: ImportWizardState = {
  file: null,
  inputType: "cve-list",
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
    return "validation failed"
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

function formatNullableNumber(value: number | null | undefined) {
  return value === null || value === undefined ? "N.A." : value.toFixed(1)
}

function formatEpss(value: number | null | undefined) {
  return value === null || value === undefined
    ? "N.A."
    : `${Math.round(value * 1000) / 10}%`
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

export function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const currentPath = normalizeWorkbenchPath(location.pathname)
  const routeDetail = routeDetails[currentPath]
  const [status, setStatus] = useState<WorkbenchStatus | null>(null)
  const [providerStatus, setProviderStatus] =
    useState<ProviderStatusPublic | null>(null)
  const [currentUser, setCurrentUser] = useState<UserPublic | null>(null)
  const [statusError, setStatusError] = useState("")
  const [projects, setProjects] = useState<ProjectPublic[]>([])
  const [selectedProjectId, setSelectedProjectId] = useState("")
  const [projectSummary, setProjectSummary] =
    useState<ProjectDecisionSummaryPublic | null>(null)
  const [projectListLoading, setProjectListLoading] = useState(true)
  const [summaryLoading, setSummaryLoading] = useState(false)
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
  const selectedProject =
    projects.find((project) => project.id === selectedProjectId) ?? null
  const dashboardLoading = projectListLoading || summaryLoading
  const dashboardCards = buildDashboardCards(
    projectSummary,
    providerStatus,
    dashboardLoading,
  )
  const summaryRows = buildSummaryRows(projectSummary)
  const findingPageStart =
    findingCount === 0 ? 0 : Math.min(findingOffset + 1, findingCount)
  const findingPageEnd = Math.min(findingOffset + findings.length, findingCount)
  const activeFindingFilters = hasActiveFindingFilters(findingFilters)

  useEffect(() => {
    let isMounted = true

    async function loadTemplateState() {
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
        }
      } catch (caught) {
        if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
          clearAccessToken()
          await navigate({ to: "/login" })
          return
        }
        if (isMounted) {
          setStatusError("Backend adapter unavailable")
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
  }, [navigate, selectedProjectId])

  useEffect(() => {
    let isMounted = true

    async function loadProjectRuns() {
      if (currentPath !== "/imports" || !selectedProjectId) {
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

    async function loadRunDetail() {
      if (currentPath !== "/imports" || !selectedRunId) {
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

    async function loadFindingsPage() {
      if (currentPath !== "/findings" || !selectedProjectId) {
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
    currentPath,
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
    navigate,
    selectedProjectId,
  ])

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
    const fileInput = event.currentTarget.elements.namedItem("importFile")
    const selectedFile =
      importWizard.file ??
      (fileInput instanceof HTMLInputElement
        ? (fileInput.files?.[0] ?? null)
        : null)
    setImportError("")
    setImportRun(null)
    setImportRunSummary(null)
    setImportParseErrors([])
    if (!selectedProjectId) {
      setImportError("Select or create a project before uploading.")
      return
    }
    if (!selectedFile) {
      setImportError("Choose an import file before uploading.")
      return
    }

    setImportLoading(true)
    try {
      const run = await ImportsService.importProjectUpload({
        projectId: selectedProjectId,
        formData: {
          file: selectedFile as unknown as string,
          input_type: importWizard.inputType,
        },
      })
      setImportRun(run)
      const summary = await RunsService.readRunSummary({ runId: run.id })
      setImportRunSummary(summary)
      setImportParseErrors(summary.parse_errors ?? [])
      setSelectedRunId(run.id)
      await refreshProjects(selectedProjectId)
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
      await refreshProjects(selectedProjectId)
      await refreshProjectRuns(runId ?? undefined)
    } finally {
      setImportLoading(false)
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
            currentPath === "/findings"
              ? "content-grid wide-workspace"
              : "content-grid"
          }
        >
          <div className="work-panel">
            <div className="panel-header">
              <div>
                <h2>{routeDetail.panelTitle}</h2>
                <span>{routeDetail.panelDetail}</span>
              </div>
              <button
                className="icon-button"
                type="button"
                aria-label={
                  currentPath === "/projects"
                    ? "Refresh projects"
                    : currentPath === "/findings"
                      ? "Refresh findings"
                      : "Refresh queue"
                }
                onClick={() => {
                  if (currentPath === "/projects") {
                    void refreshProjects(selectedProjectId)
                  }
                  if (currentPath === "/findings") {
                    refreshFindings()
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
            ) : currentPath === "/findings" ? (
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
                              <strong>{finding.cve_id}</strong>
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
            <div className="coverage-block">
              <BarChart3 aria-hidden="true" size={20} />
              <div>
                <strong>ATT&CK coverage</strong>
                <span>
                  Top technique gaps remain visible for the next API slice.
                </span>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}

const fallbackProviderSources = [
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
