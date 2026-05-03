import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import {
  Activity,
  BriefcaseBusiness,
  Database,
  FileInput,
  Globe2,
  RefreshCw,
  Server,
  ShieldCheck,
  Users,
} from "lucide-react"
import { type FormEvent, useEffect, useMemo, useState } from "react"
import {
  ApiError,
  type AssetCreate,
  type AssetCriticality,
  type AssetEnvironment,
  type AssetExposure,
  type AssetPublic,
  AssetsService,
  type AssetUpdate,
  type FindingPublic,
  FindingsService,
  type ProjectPublic,
  ProjectsService,
  type ProviderStatusPublic,
  ProvidersService,
  type UserPublic,
  UsersService,
  WorkbenchService,
  type WorkbenchStatus,
} from "../../api-client"
import { clearAccessToken } from "../../auth"
import { ProductAppShell } from "../../components/app/AppShell"
import { Button } from "../../components/ui/button"
import { Input } from "../../components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../../components/ui/select"
import {
  VpwAssetContextCard,
  VpwBadge,
  type VpwBadgeTone,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwField,
  VpwFilterBar,
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPageContainer,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwSelectionCard,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwToolbar,
  VpwToolbarGroup,
} from "../../components/vpw"
import {
  providerSnapshotHealth,
  providerSnapshotSummary,
} from "../../lib/provider-format"
import { formatLabel as labelize, optionalText } from "../../lib/ui-copy"

const criticalityOptions: AssetCriticality[] = [
  "critical",
  "high",
  "medium",
  "low",
  "unknown",
]
const environmentOptions: AssetEnvironment[] = [
  "production",
  "staging",
  "development",
  "test",
  "unknown",
]
const exposureOptions: AssetExposure[] = [
  "internet-facing",
  "internal",
  "private",
  "unknown",
]

type AssetFormState = {
  asset_key: string
  business_service: string
  criticality: AssetCriticality
  environment: AssetEnvironment
  exposure: AssetExposure
  name: string
  owner: string
  target_ref: string
}

const emptyAssetForm: AssetFormState = {
  asset_key: "",
  business_service: "",
  criticality: "unknown",
  environment: "unknown",
  exposure: "unknown",
  name: "",
  owner: "",
  target_ref: "",
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
    return typeof record.message === "string" && record.message.trim()
      ? record.message
      : null
  }
  return null
}

function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "N.A."
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "N.A."
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date)
}

function assetFormFromAsset(asset: AssetPublic): AssetFormState {
  return {
    asset_key: asset.asset_key,
    business_service: asset.business_service ?? "",
    criticality: asset.criticality ?? "unknown",
    environment: asset.environment ?? "unknown",
    exposure: asset.exposure ?? "unknown",
    name: asset.name,
    owner: asset.owner ?? "",
    target_ref: asset.target_ref ?? "",
  }
}

function cleanOptional(value: string) {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

function assetRequestBody(form: AssetFormState): AssetCreate {
  return {
    asset_key: form.asset_key.trim(),
    business_service: cleanOptional(form.business_service),
    criticality: form.criticality,
    environment: form.environment,
    exposure: form.exposure,
    name: form.name.trim(),
    owner: cleanOptional(form.owner),
    target_ref: cleanOptional(form.target_ref),
  }
}

function assetUpdateBody(form: AssetFormState): AssetUpdate {
  return assetRequestBody(form)
}

function validateAssetForm(form: AssetFormState) {
  if (!form.asset_key.trim()) {
    return "Asset key is required."
  }
  if (!form.name.trim()) {
    return "Asset name is required."
  }
  if (!criticalityOptions.includes(form.criticality)) {
    return "Criticality must be a supported value."
  }
  if (!environmentOptions.includes(form.environment)) {
    return "Environment must be a supported value."
  }
  if (!exposureOptions.includes(form.exposure)) {
    return "Exposure must be a supported value."
  }
  return ""
}

function matchesAsset(finding: FindingPublic, asset: AssetPublic) {
  return (
    finding.asset_id === asset.id ||
    finding.asset_key === asset.asset_key ||
    finding.asset_name === asset.name
  )
}

function findingAssetLabel(finding: FindingPublic) {
  return (
    finding.asset_name ??
    finding.asset_key ??
    finding.business_service ??
    "N.A."
  )
}

function assetFindingsHref(asset: AssetPublic) {
  const params = new URLSearchParams({
    assetId: asset.id,
    assetKey: asset.asset_key,
  })
  return `/findings?${params.toString()}`
}

function criticalityTone(
  value: AssetCriticality | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "critical":
      return "critical"
    case "high":
      return "warning"
    case "medium":
      return "info"
    case "low":
      return "success"
    default:
      return "neutral"
  }
}

function exposureTone(
  value: AssetExposure | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "internet-facing":
      return "warning"
    case "internal":
      return "info"
    case "private":
      return "success"
    default:
      return "neutral"
  }
}

function environmentTone(
  value: AssetEnvironment | string | null | undefined,
): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "production":
      return "warning"
    case "staging":
    case "test":
      return "info"
    case "development":
      return "support"
    default:
      return "neutral"
  }
}

function findingPriorityTone(value: string | null | undefined): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "critical":
      return "critical"
    case "high":
      return "warning"
    case "medium":
      return "info"
    case "low":
      return "success"
    default:
      return "neutral"
  }
}

function findingStatusTone(value: string | null | undefined): VpwBadgeTone {
  switch (String(value ?? "").toLowerCase()) {
    case "resolved":
    case "accepted":
    case "false_positive":
      return "success"
    case "in_progress":
    case "triaged":
      return "info"
    case "deferred":
      return "warning"
    default:
      return "neutral"
  }
}

function assetScoreTone(asset: AssetPublic): VpwBadgeTone {
  return asset.rescore_needed ? "warning" : "success"
}

function scoreStatusLabel(asset: AssetPublic) {
  return asset.rescore_needed ? "Re-score needed" : "Current"
}

function highestFindingPriority(findings: readonly FindingPublic[]) {
  const order = ["critical", "high", "medium", "low"]
  const priorities = findings
    .map((finding) => String(finding.priority ?? "").toLowerCase())
    .filter(Boolean)
  const highest = order.find((priority) => priorities.includes(priority))
  return highest ? labelize(highest) : "N.A."
}

type AssetSummary = {
  criticalServices: number
  internetFacing: number
  linkedFindings: number
  ownerCoverage: number
  production: number
  total: number
}

function summarizeAssets(assets: readonly AssetPublic[]): AssetSummary {
  const total = assets.length
  const ownerCount = assets.filter((asset) => asset.owner?.trim()).length
  const criticalServices = new Set(
    assets
      .filter((asset) =>
        ["critical", "high"].includes(String(asset.criticality ?? "")),
      )
      .map((asset) => asset.business_service || asset.name || asset.asset_key),
  ).size

  return {
    criticalServices,
    internetFacing: assets.filter(
      (asset) => asset.exposure === "internet-facing",
    ).length,
    linkedFindings: assets.reduce(
      (totalFindings, asset) => totalFindings + (asset.finding_count ?? 0),
      0,
    ),
    ownerCoverage: total > 0 ? Math.round((ownerCount / total) * 100) : 0,
    production: assets.filter((asset) => asset.environment === "production")
      .length,
    total,
  }
}

type ServiceRollup = {
  assetCount: number
  criticalAssets: number
  exposure: string
  findings: number
  id: string
  label: string
  owner: string
}

function buildServiceRollups(assets: readonly AssetPublic[]): ServiceRollup[] {
  const rollups = new Map<string, ServiceRollup>()

  for (const asset of assets) {
    const label = asset.business_service || "Unassigned service"
    const existing = rollups.get(label) ?? {
      assetCount: 0,
      criticalAssets: 0,
      exposure: "unknown",
      findings: 0,
      id: label,
      label,
      owner: "N.A.",
    }

    existing.assetCount += 1
    existing.findings += asset.finding_count ?? 0
    if (["critical", "high"].includes(String(asset.criticality ?? ""))) {
      existing.criticalAssets += 1
    }
    if (asset.owner && existing.owner === "N.A.") {
      existing.owner = asset.owner
    }
    if (asset.exposure === "internet-facing") {
      existing.exposure = "internet-facing"
    } else if (
      existing.exposure === "unknown" &&
      asset.exposure &&
      asset.exposure !== "unknown"
    ) {
      existing.exposure = asset.exposure
    }

    rollups.set(label, existing)
  }

  return [...rollups.values()].sort((left, right) => {
    const riskDelta = right.criticalAssets - left.criticalAssets
    return riskDelta !== 0 ? riskDelta : right.findings - left.findings
  })
}

function AssetForm({
  buttonLabel,
  disabled,
  error,
  form,
  formLabel,
  onChange,
  onSubmit,
}: {
  buttonLabel: string
  disabled: boolean
  error: string
  form: AssetFormState
  formLabel: string
  onChange: (form: AssetFormState) => void
  onSubmit: (event: FormEvent<HTMLFormElement>) => void
}) {
  const isEdit = formLabel.includes("Edit")
  const fieldPrefix = isEdit ? "edit-asset" : "create-asset"

  return (
    <form aria-label={formLabel} className="space-y-4" onSubmit={onSubmit}>
      <VpwGrid columns={2}>
        <VpwField
          htmlFor={`${fieldPrefix}-asset-key`}
          label="Asset key"
          required
        >
          <Input
            aria-label={isEdit ? "Edit asset key" : "Asset key"}
            id={`${fieldPrefix}-asset-key`}
            maxLength={255}
            onChange={(event) =>
              onChange({ ...form, asset_key: event.target.value })
            }
            placeholder="app-prod-01"
            value={form.asset_key}
          />
        </VpwField>
        <VpwField
          htmlFor={`${fieldPrefix}-asset-name`}
          label="Asset name"
          required
        >
          <Input
            aria-label={isEdit ? "Edit asset name" : "Asset name"}
            id={`${fieldPrefix}-asset-name`}
            maxLength={255}
            onChange={(event) =>
              onChange({ ...form, name: event.target.value })
            }
            placeholder="Payments API"
            value={form.name}
          />
        </VpwField>
        <VpwField htmlFor={`${fieldPrefix}-owner`} label="Owner">
          <Input
            aria-label={isEdit ? "Edit owner" : "Owner"}
            id={`${fieldPrefix}-owner`}
            maxLength={255}
            onChange={(event) =>
              onChange({ ...form, owner: event.target.value })
            }
            placeholder="Platform security"
            value={form.owner}
          />
        </VpwField>
        <VpwField
          htmlFor={`${fieldPrefix}-business-service`}
          label="Business service"
        >
          <Input
            aria-label={isEdit ? "Edit business service" : "Business service"}
            id={`${fieldPrefix}-business-service`}
            maxLength={255}
            onChange={(event) =>
              onChange({ ...form, business_service: event.target.value })
            }
            placeholder="Checkout"
            value={form.business_service}
          />
        </VpwField>
        <VpwField
          className="lg:col-span-2"
          htmlFor={`${fieldPrefix}-target-ref`}
          label="Target ref"
        >
          <Input
            aria-label={isEdit ? "Edit target ref" : "Target ref"}
            id={`${fieldPrefix}-target-ref`}
            maxLength={512}
            onChange={(event) =>
              onChange({ ...form, target_ref: event.target.value })
            }
            placeholder="image:registry.example.com/payments-api"
            value={form.target_ref}
          />
        </VpwField>
        <VpwField label="Criticality">
          <Select
            onValueChange={(value) =>
              onChange({
                ...form,
                criticality: value as AssetCriticality,
              })
            }
            value={form.criticality}
          >
            <SelectTrigger
              aria-label={isEdit ? "Edit criticality" : "Criticality"}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {criticalityOptions.map((option) => (
                <SelectItem key={option} value={option}>
                  {labelize(option)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </VpwField>
        <VpwField label="Environment">
          <Select
            onValueChange={(value) =>
              onChange({
                ...form,
                environment: value as AssetEnvironment,
              })
            }
            value={form.environment}
          >
            <SelectTrigger
              aria-label={isEdit ? "Edit environment" : "Environment"}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {environmentOptions.map((option) => (
                <SelectItem key={option} value={option}>
                  {labelize(option)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </VpwField>
        <VpwField label="Exposure">
          <Select
            onValueChange={(value) =>
              onChange({
                ...form,
                exposure: value as AssetExposure,
              })
            }
            value={form.exposure}
          >
            <SelectTrigger aria-label={isEdit ? "Edit exposure" : "Exposure"}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {exposureOptions.map((option) => (
                <SelectItem key={option} value={option}>
                  {labelize(option)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </VpwField>
      </VpwGrid>
      {error ? (
        <VpwStatusBanner title="Asset form needs attention" tone="critical">
          {error}
        </VpwStatusBanner>
      ) : null}
      <Button disabled={disabled} type="submit">
        {buttonLabel}
      </Button>
    </form>
  )
}

function AssetsPage() {
  const navigate = useNavigate()
  const [status, setStatus] = useState<WorkbenchStatus | null>(null)
  const [providerStatus, setProviderStatus] =
    useState<ProviderStatusPublic | null>(null)
  const [currentUser, setCurrentUser] = useState<UserPublic | null>(null)
  const [statusError, setStatusError] = useState("")
  const [projects, setProjects] = useState<ProjectPublic[]>([])
  const [selectedProjectId, setSelectedProjectId] = useState("")
  const [projectLoading, setProjectLoading] = useState(true)
  const [assets, setAssets] = useState<AssetPublic[]>([])
  const [assetsLoading, setAssetsLoading] = useState(false)
  const [assetsError, setAssetsError] = useState("")
  const [assetOwnerFilter, setAssetOwnerFilter] = useState("")
  const [assetServiceFilter, setAssetServiceFilter] = useState("")
  const [assetMessage, setAssetMessage] = useState("")
  const [assetActionLoading, setAssetActionLoading] = useState(false)
  const [assetContextFile, setAssetContextFile] = useState<File | null>(null)
  const [createForm, setCreateForm] = useState<AssetFormState>(emptyAssetForm)
  const [createError, setCreateError] = useState("")
  const [editForm, setEditForm] = useState<AssetFormState>(emptyAssetForm)
  const [editError, setEditError] = useState("")
  const [editingAssetId, setEditingAssetId] = useState("")
  const [selectedAssetId, setSelectedAssetId] = useState("")
  const [assetFindings, setAssetFindings] = useState<FindingPublic[]>([])
  const [assetFindingsLoading, setAssetFindingsLoading] = useState(false)
  const [assetFindingsError, setAssetFindingsError] = useState("")
  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId) ?? null,
    [projects, selectedProjectId],
  )
  const selectedAsset = useMemo(
    () => assets.find((asset) => asset.id === selectedAssetId) ?? null,
    [assets, selectedAssetId],
  )

  async function handleUnauthorized(caught: unknown) {
    if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
      clearAccessToken()
      await navigate({ to: "/login" })
      return true
    }
    return false
  }

  async function refreshProjects(preferredProjectId?: string) {
    setProjectLoading(true)
    try {
      const projectPage = await ProjectsService.readProjects()
      setProjects(projectPage.data)
      setSelectedProjectId((currentProjectId) => {
        if (
          preferredProjectId &&
          projectPage.data.some((project) => project.id === preferredProjectId)
        ) {
          return preferredProjectId
        }
        if (
          projectPage.data.some((project) => project.id === currentProjectId)
        ) {
          return currentProjectId
        }
        return projectPage.data[0]?.id ?? ""
      })
    } catch (caught) {
      if (await handleUnauthorized(caught)) {
        return
      }
      setProjects([])
      setSelectedProjectId("")
      setAssetsError(apiErrorMessage("Project list unavailable", caught))
    } finally {
      setProjectLoading(false)
    }
  }

  async function refreshAssets(preferredAssetId?: string) {
    if (!selectedProjectId) {
      setAssets([])
      setSelectedAssetId("")
      return
    }
    setAssetsLoading(true)
    setAssetsError("")
    try {
      const assetPage = await AssetsService.readProjectAssets({
        owner: assetOwnerFilter.trim() || undefined,
        project_id: selectedProjectId,
        service: assetServiceFilter.trim() || undefined,
      })
      setAssets(assetPage.data)
      setSelectedAssetId((currentAssetId) => {
        if (
          preferredAssetId &&
          assetPage.data.some((asset) => asset.id === preferredAssetId)
        ) {
          return preferredAssetId
        }
        if (assetPage.data.some((asset) => asset.id === currentAssetId)) {
          return currentAssetId
        }
        return assetPage.data[0]?.id ?? ""
      })
    } catch (caught) {
      if (await handleUnauthorized(caught)) {
        return
      }
      setAssets([])
      setSelectedAssetId("")
      setAssetsError(apiErrorMessage("Assets unavailable", caught))
    } finally {
      setAssetsLoading(false)
    }
  }

  useEffect(() => {
    let isMounted = true

    async function loadShell() {
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
        if (await handleUnauthorized(caught)) {
          return
        }
        if (isMounted) {
          setStatusError("Data services unavailable")
        }
      }
    }

    void loadShell()
    void refreshProjects()
    return () => {
      isMounted = false
    }
  }, [])

  useEffect(() => {
    void refreshAssets()
  }, [assetOwnerFilter, assetServiceFilter, selectedProjectId])

  useEffect(() => {
    let isMounted = true

    async function loadAssetFindings() {
      if (!selectedProjectId || !selectedAsset) {
        setAssetFindings([])
        setAssetFindingsError("")
        setAssetFindingsLoading(false)
        return
      }
      setAssetFindingsLoading(true)
      setAssetFindingsError("")
      try {
        const page = await FindingsService.readProjectFindings({
          asset_id: selectedAsset.id,
          limit: 200,
          offset: 0,
          project_id: selectedProjectId,
          sort: "operational",
        })
        if (isMounted) {
          setAssetFindings(
            page.data.filter((finding) => matchesAsset(finding, selectedAsset)),
          )
        }
      } catch (caught) {
        if (await handleUnauthorized(caught)) {
          return
        }
        if (isMounted) {
          setAssetFindings([])
          setAssetFindingsError(
            apiErrorMessage("Asset findings unavailable", caught),
          )
        }
      } finally {
        if (isMounted) {
          setAssetFindingsLoading(false)
        }
      }
    }

    void loadAssetFindings()
    return () => {
      isMounted = false
    }
  }, [selectedAsset, selectedProjectId])

  async function createAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setCreateError("")
    setAssetMessage("")
    setAssetsError("")
    const validationError = validateAssetForm(createForm)
    if (validationError) {
      setCreateError(validationError)
      return
    }
    if (!selectedProjectId) {
      setCreateError("Select a project before creating an asset.")
      return
    }

    setAssetActionLoading(true)
    try {
      const asset = await AssetsService.createProjectAsset({
        project_id: selectedProjectId,
        assetCreate: assetRequestBody(createForm),
      })
      setCreateForm(emptyAssetForm)
      setAssetMessage(`Asset ${asset.name} created.`)
      await refreshAssets(asset.id)
    } catch (caught) {
      if (await handleUnauthorized(caught)) {
        return
      }
      setAssetsError(apiErrorMessage("Asset create failed", caught))
    } finally {
      setAssetActionLoading(false)
    }
  }

  function startEditAsset(asset: AssetPublic) {
    setEditingAssetId(asset.id)
    setEditForm(assetFormFromAsset(asset))
    setEditError("")
    setAssetMessage("")
    setAssetsError("")
  }

  async function saveAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!editingAssetId) {
      return
    }
    setEditError("")
    setAssetsError("")
    setAssetMessage("")
    const validationError = validateAssetForm(editForm)
    if (validationError) {
      setEditError(validationError)
      return
    }

    setAssetActionLoading(true)
    try {
      const asset = await AssetsService.updateAsset({
        asset_id: editingAssetId,
        assetUpdate: assetUpdateBody(editForm),
      })
      setEditingAssetId("")
      setAssetMessage(`Asset ${asset.name} updated.`)
      await refreshAssets(asset.id)
    } catch (caught) {
      if (await handleUnauthorized(caught)) {
        return
      }
      setAssetsError(apiErrorMessage("Asset update failed", caught))
    } finally {
      setAssetActionLoading(false)
    }
  }

  async function recalculateAsset(asset: AssetPublic) {
    setAssetsError("")
    setAssetMessage("")
    setAssetActionLoading(true)
    try {
      const result = await AssetsService.recalculateAsset({
        asset_id: asset.id,
      })
      setAssetMessage(
        `Recalculated ${result.recalculated_findings} finding(s) for ${asset.name}.`,
      )
      await refreshAssets(asset.id)
    } catch (caught) {
      if (await handleUnauthorized(caught)) {
        return
      }
      setAssetsError(apiErrorMessage("Asset recalculation failed", caught))
    } finally {
      setAssetActionLoading(false)
    }
  }

  async function importAssetContext(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setAssetsError("")
    setAssetMessage("")
    if (!selectedProjectId) {
      setAssetsError("Select a project before importing asset context.")
      return
    }
    if (!assetContextFile) {
      setAssetsError("Choose an asset context CSV before importing.")
      return
    }

    setAssetActionLoading(true)
    try {
      const result = await AssetsService.importProjectAssets({
        project_id: selectedProjectId,
        bodyAssetsImportProjectAssets: {
          asset_context_file: assetContextFile,
        },
      })
      setAssetContextFile(null)
      setAssetMessage(
        `Imported ${result.imported_assets} asset(s); ${result.rescore_needed_findings} finding(s) need recalculation.`,
      )
      await refreshAssets(selectedAssetId)
    } catch (caught) {
      if (await handleUnauthorized(caught)) {
        return
      }
      setAssetsError(apiErrorMessage("Asset context import failed", caught))
    } finally {
      setAssetActionLoading(false)
    }
  }

  const assetSummary = summarizeAssets(assets)
  const serviceRollups = buildServiceRollups(assets)
  const selectedHighestPriority = highestFindingPriority(assetFindings)
  const activeProjectLabel =
    selectedProject?.name ?? (projectLoading ? "Loading" : "No project")
  const projectSelectDisabled = projectLoading || projects.length === 0

  const assetColumns: readonly VpwDataTableColumn<AssetPublic>[] = [
    {
      cell: (asset) => (
        <Button
          aria-current={selectedAssetId === asset.id ? "true" : undefined}
          className="h-auto justify-start px-2 py-1 text-left"
          onClick={() => setSelectedAssetId(asset.id)}
          type="button"
          variant="ghost"
        >
          <span className="grid min-w-44 gap-0.5">
            <span className="font-semibold text-[var(--vpw-text-primary)]">
              {asset.name}
            </span>
            <span className="font-mono text-xs text-[var(--vpw-text-muted)]">
              {asset.target_ref ?? asset.asset_key}
            </span>
          </span>
        </Button>
      ),
      header: "Asset / target ref",
      id: "asset",
    },
    {
      cell: (asset) => optionalText(asset.business_service),
      header: "Service",
      id: "service",
    },
    {
      cell: (asset) => optionalText(asset.owner),
      header: "Owner",
      id: "owner",
    },
    {
      cell: (asset) => (
        <VpwBadge tone={environmentTone(asset.environment)}>
          {labelize(asset.environment)}
        </VpwBadge>
      ),
      header: "Environment",
      id: "environment",
    },
    {
      cell: (asset) => (
        <VpwBadge tone={exposureTone(asset.exposure)}>
          {labelize(asset.exposure)}
        </VpwBadge>
      ),
      header: "Exposure",
      id: "exposure",
    },
    {
      cell: (asset) => (
        <VpwBadge tone={criticalityTone(asset.criticality)}>
          {labelize(asset.criticality)}
        </VpwBadge>
      ),
      header: "Criticality",
      id: "criticality",
    },
    {
      cell: (asset) => asset.finding_count ?? 0,
      header: "Findings",
      id: "findings",
    },
    {
      cell: (asset) => {
        const value =
          asset.id === selectedAssetId
            ? selectedHighestPriority
            : asset.finding_count
              ? "Linked"
              : "None"
        return <VpwBadge tone={findingPriorityTone(value)}>{value}</VpwBadge>
      },
      header: "Highest priority",
      id: "highest-priority",
    },
    {
      cell: (asset) => (
        <VpwBadge tone={assetScoreTone(asset)}>
          {scoreStatusLabel(asset)}
        </VpwBadge>
      ),
      header: "Score state",
      id: "score-state",
    },
    {
      cell: (asset) => formatDateTime(asset.updated_at),
      header: "Updated",
      id: "updated",
    },
    {
      cell: (asset) => (
        <div className="flex min-w-52 flex-wrap gap-2">
          <Button asChild size="sm" variant="outline">
            <a href={assetFindingsHref(asset)}>Findings</a>
          </Button>
          <Button
            onClick={() => {
              setSelectedAssetId(asset.id)
              startEditAsset(asset)
            }}
            size="sm"
            type="button"
            variant="outline"
          >
            Edit
          </Button>
          <Button
            aria-label={`Recalculate ${asset.name}`}
            disabled={assetActionLoading || (asset.finding_count ?? 0) === 0}
            onClick={() => void recalculateAsset(asset)}
            size="sm"
            type="button"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" />
            Recalculate
          </Button>
        </div>
      ),
      header: "Actions",
      id: "actions",
    },
  ]

  const findingColumns: readonly VpwDataTableColumn<FindingPublic>[] = [
    {
      cell: (finding) => (
        <VpwBadge tone={findingPriorityTone(finding.priority)}>
          {labelize(finding.priority)}
        </VpwBadge>
      ),
      header: "Priority",
      id: "priority",
    },
    {
      cell: (finding) => (
        <Link
          className="font-mono text-sm font-semibold text-[var(--vpw-blue)] hover:underline"
          params={{ findingId: finding.id }}
          to="/findings/$findingId"
        >
          {finding.cve_id}
        </Link>
      ),
      header: "CVE",
      id: "cve",
    },
    {
      cell: (finding) => optionalText(finding.component_name),
      header: "Component",
      id: "component",
    },
    {
      cell: (finding) => findingAssetLabel(finding),
      header: "Asset",
      id: "asset",
    },
    {
      cell: (finding) => (
        <VpwBadge tone={findingStatusTone(finding.status)}>
          {labelize(finding.status)}
        </VpwBadge>
      ),
      header: "Status",
      id: "status",
    },
  ]

  return (
    <ProductAppShell
      activePath="/assets"
      currentUser={currentUser}
      eyebrow="Workbench Assets"
      providerStatus={providerStatus}
      status={status}
      statusError={statusError}
      title="Assets"
    >
      <VpwPageContainer className="space-y-6">
        <VpwSection>
          <VpwPanel className="space-y-5 p-5">
            <VpwSectionHeader
              description="Manage asset, service, exposure and owner context for risk-based prioritization."
              eyebrow="Asset exposure"
              title="Assets"
            />
            <VpwToolbar label="Asset actions">
              <VpwToolbarGroup>
                <Button asChild>
                  <a href="#asset-context-import">
                    <FileInput aria-hidden="true" />
                    Import context
                  </a>
                </Button>
                <Button asChild variant="outline">
                  <Link to="/findings">View findings</Link>
                </Button>
                <Button
                  aria-label="Refresh assets"
                  disabled={assetsLoading}
                  onClick={() => void refreshAssets(selectedAssetId)}
                  type="button"
                  variant="outline"
                >
                  <Activity aria-hidden="true" />
                  Refresh
                </Button>
              </VpwToolbarGroup>
            </VpwToolbar>
            <VpwToolbar className="overflow-hidden" label="Asset page context">
              <VpwToolbarGroup className="min-w-0">
                <VpwBadge
                  className="max-w-full whitespace-normal text-left [overflow-wrap:anywhere]"
                  tone="info"
                >
                  Active project: {activeProjectLabel}
                </VpwBadge>
                <VpwBadge tone="neutral">Assets: {assetSummary.total}</VpwBadge>
                <VpwBadge tone="warning">
                  Internet-facing: {assetSummary.internetFacing}
                </VpwBadge>
                <VpwBadge tone="critical">
                  Critical services: {assetSummary.criticalServices}
                </VpwBadge>
                <VpwBadge tone="support">
                  Owner coverage: {assetSummary.ownerCoverage}%
                </VpwBadge>
              </VpwToolbarGroup>
            </VpwToolbar>
            <VpwStatusBanner
              title="Provider snapshot"
              tone={providerStatus?.status === "ok" ? "success" : "warning"}
            >
              {providerSnapshotSummary(providerStatus)} -{" "}
              {providerSnapshotHealth(providerStatus)} - snapshot mode{" "}
              {providerStatus?.snapshot_mode ?? "missing"}.
            </VpwStatusBanner>
          </VpwPanel>
        </VpwSection>

        {assetsError ? (
          <VpwStatusBanner title="Asset action failed" tone="critical">
            {assetsError}
          </VpwStatusBanner>
        ) : null}
        {assetMessage ? (
          <VpwStatusBanner title="Asset context updated" tone="success">
            {assetMessage}
          </VpwStatusBanner>
        ) : null}
        {projectLoading || assetsLoading ? (
          <VpwStatusBanner title="Loading asset context" tone="info">
            Refreshing project assets and linked finding counts.
          </VpwStatusBanner>
        ) : null}

        <VpwGrid columns={1} className="lg:grid-cols-2 xl:grid-cols-4">
          <VpwMetricCard
            description="Assets and target references in scope"
            icon={<Server aria-hidden="true" />}
            label="Total assets"
            value={assetSummary.total}
          />
          <VpwMetricCard
            description="Assets with external exposure"
            icon={<Globe2 aria-hidden="true" />}
            label="Internet-facing"
            tone="warning"
            value={assetSummary.internetFacing}
          />
          <VpwMetricCard
            description="Production environment context"
            icon={<ShieldCheck aria-hidden="true" />}
            label="Production assets"
            tone="info"
            value={assetSummary.production}
          />
          <VpwMetricCard
            description={`${assetSummary.ownerCoverage}% of assets have an owner`}
            icon={<Users aria-hidden="true" />}
            label="Owner coverage"
            tone="support"
            value={`${assetSummary.ownerCoverage}%`}
          />
        </VpwGrid>

        <VpwGrid columns={2}>
          <div id="asset-context-import">
            <VpwPanel className="space-y-4 p-5">
              <VpwSectionHeader
                description="Upload CSV context to update asset ownership, service, environment, exposure and criticality."
                eyebrow="Context intake"
                title="Import asset context"
              />
              <form
                aria-label="Import Asset Context form fields"
                className="space-y-4"
                onSubmit={importAssetContext}
              >
                <VpwField
                  description="Accepted columns include target ref, target kind, asset id, owner, business service, environment, exposure and criticality."
                  htmlFor="asset-context-csv"
                  label="Asset context CSV"
                >
                  <Input
                    accept=".csv,text/csv"
                    aria-label="Asset context CSV"
                    id="asset-context-csv"
                    onChange={(event) =>
                      setAssetContextFile(event.target.files?.[0] ?? null)
                    }
                    type="file"
                  />
                </VpwField>
                <Button
                  disabled={
                    assetActionLoading ||
                    projects.length === 0 ||
                    !assetContextFile
                  }
                  type="submit"
                >
                  <FileInput aria-hidden="true" />
                  Upload context
                </Button>
              </form>
              <VpwKeyValueList
                columns={2}
                items={[
                  {
                    label: "Selected file",
                    value: assetContextFile?.name ?? "None selected",
                  },
                  {
                    label: "Target project",
                    value: activeProjectLabel,
                  },
                ]}
              />
            </VpwPanel>
          </div>

          <VpwPanel className="space-y-4 p-5">
            <VpwSectionHeader
              description="Create a single asset context record when a CSV import is not needed."
              eyebrow="Manual context"
              title="Create asset"
            />
            <AssetForm
              buttonLabel="Create Asset"
              disabled={assetActionLoading || projects.length === 0}
              error={createError}
              form={createForm}
              formLabel="Create Asset form fields"
              onChange={setCreateForm}
              onSubmit={createAsset}
            />
          </VpwPanel>
        </VpwGrid>

        <VpwSection>
          <VpwSectionHeader
            actions={
              <Button
                disabled={projectSelectDisabled}
                onClick={() => void refreshAssets(selectedAssetId)}
                type="button"
                variant="outline"
              >
                <RefreshCw aria-hidden="true" />
                Refresh
              </Button>
            }
            description="Filter project assets by service and owner, then inspect the context that changes prioritization."
            eyebrow="In-scope assets"
            title="Asset inventory"
          />
          <VpwFilterBar
            actions={
              <Button
                disabled={!assetOwnerFilter && !assetServiceFilter}
                onClick={() => {
                  setAssetOwnerFilter("")
                  setAssetServiceFilter("")
                }}
                type="button"
                variant="outline"
              >
                Clear filters
              </Button>
            }
            onSearchChange={setAssetServiceFilter}
            searchLabel="Asset service filter"
            searchPlaceholder="Filter by service"
            searchValue={assetServiceFilter}
          >
            <VpwField className="min-w-52" label="Owner">
              <Input
                aria-label="Asset owner filter"
                onChange={(event) => setAssetOwnerFilter(event.target.value)}
                placeholder="Filter owner"
                value={assetOwnerFilter}
              />
            </VpwField>
            <VpwField className="min-w-64" label="Project">
              <Select
                disabled={projectSelectDisabled}
                onValueChange={(projectId) => {
                  setSelectedProjectId(projectId)
                  setEditingAssetId("")
                  setAssetMessage("")
                }}
                value={selectedProjectId}
              >
                <SelectTrigger aria-label="Assets project">
                  <SelectValue placeholder="Select project" />
                </SelectTrigger>
                <SelectContent>
                  {projects.map((project) => (
                    <SelectItem key={project.id} value={project.id}>
                      {project.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </VpwField>
          </VpwFilterBar>

          {projects.length === 0 && !projectLoading ? (
            <VpwEmptyState
              action={
                <Button asChild>
                  <Link to="/projects">Create project</Link>
                </Button>
              }
              icon={<BriefcaseBusiness aria-hidden="true" />}
              title="No projects yet"
              description="Create a project before managing asset context."
            />
          ) : null}

          {!assetsLoading && selectedProject && assets.length === 0 ? (
            <VpwEmptyState
              action={
                <Button asChild variant="outline">
                  <a href="#asset-context-import">Import asset context</a>
                </Button>
              }
              icon={<Server aria-hidden="true" />}
              title="No asset context yet"
              description="Import asset context to improve prioritization and ownership."
            />
          ) : null}

          {assetsLoading ? (
            <VpwPanel className="p-5">
              <VpwSkeletonStack rows={6} />
            </VpwPanel>
          ) : null}

          {assets.length > 0 ? (
            <VpwDataTable
              caption="Assets table"
              columns={assetColumns}
              data={assets}
              density="compact"
              getRowKey={(asset) => asset.id}
            />
          ) : null}
        </VpwSection>

        {serviceRollups.length > 0 ? (
          <VpwSection>
            <VpwSectionHeader
              description="Rollup by business service and owner for faster exposure review."
              eyebrow="Service exposure"
              title="Service and owner rollup"
            />
            <VpwGrid columns={1} className="lg:grid-cols-2 xl:grid-cols-4">
              {serviceRollups.slice(0, 8).map((rollup) => (
                <VpwSelectionCard
                  key={rollup.id}
                  meta={`${rollup.assetCount} assets - ${rollup.findings} findings`}
                  onClick={() => setAssetServiceFilter(rollup.label)}
                  title={rollup.label}
                >
                  <div className="space-y-3">
                    <div className="flex flex-wrap gap-2">
                      <VpwBadge tone="support">{rollup.owner}</VpwBadge>
                      <VpwBadge tone={exposureTone(rollup.exposure)}>
                        {labelize(rollup.exposure)}
                      </VpwBadge>
                      <VpwBadge
                        tone={rollup.criticalAssets > 0 ? "warning" : "success"}
                      >
                        {rollup.criticalAssets} critical/high
                      </VpwBadge>
                    </div>
                    <VpwProgress
                      label="Evidence readiness"
                      tone={rollup.findings > 0 ? "info" : "neutral"}
                      value={rollup.findings > 0 ? 66 : 20}
                    />
                  </div>
                </VpwSelectionCard>
              ))}
            </VpwGrid>
          </VpwSection>
        ) : null}

        {selectedAsset ? (
          <VpwSection>
            <VpwSectionHeader
              actions={
                <VpwToolbarGroup>
                  <Button
                    onClick={() => startEditAsset(selectedAsset)}
                    type="button"
                    variant="outline"
                  >
                    Edit context
                  </Button>
                  <Button
                    disabled={
                      assetActionLoading ||
                      (selectedAsset.finding_count ?? 0) === 0
                    }
                    onClick={() => void recalculateAsset(selectedAsset)}
                    type="button"
                    variant="outline"
                  >
                    <RefreshCw aria-hidden="true" />
                    Recalculate
                  </Button>
                  <Button asChild variant="outline">
                    <a href={assetFindingsHref(selectedAsset)}>View findings</a>
                  </Button>
                </VpwToolbarGroup>
              }
              description="Selected asset context and linked findings for the active project."
              eyebrow="Asset detail"
              title={selectedAsset.name}
            />
            <VpwGrid columns={2}>
              <div className="space-y-4">
                <VpwAssetContextCard
                  asset={selectedAsset.asset_key}
                  businessService={optionalText(selectedAsset.business_service)}
                  criticality={labelize(selectedAsset.criticality)}
                  exposure={labelize(selectedAsset.exposure)}
                  owner={optionalText(selectedAsset.owner)}
                />
                <VpwPanel className="space-y-4 p-5">
                  <VpwSectionHeader
                    eyebrow="Metadata"
                    title="Prioritization context"
                    description="These fields are used by the Workbench backend when linked findings are recalculated."
                  />
                  <VpwKeyValueList
                    columns={2}
                    items={[
                      {
                        label: "Target ref",
                        value: optionalText(selectedAsset.target_ref),
                      },
                      {
                        label: "Findings linked",
                        value: selectedAsset.finding_count ?? 0,
                      },
                      {
                        label: "Highest priority",
                        value: selectedHighestPriority,
                        tone: findingPriorityTone(selectedHighestPriority),
                      },
                      {
                        label: "Score state",
                        value: scoreStatusLabel(selectedAsset),
                        tone: assetScoreTone(selectedAsset),
                      },
                      {
                        label: "Updated",
                        value: formatDateTime(selectedAsset.updated_at),
                      },
                      {
                        label: "Created",
                        value: formatDateTime(selectedAsset.created_at),
                      },
                    ]}
                  />
                </VpwPanel>
              </div>

              <VpwPanel className="space-y-4 p-5">
                {editingAssetId === selectedAsset.id ? (
                  <>
                    <VpwSectionHeader
                      description="Update asset owner, service, exposure, environment and criticality."
                      eyebrow="Edit context"
                      title="Edit selected asset"
                    />
                    <AssetForm
                      buttonLabel="Save Asset"
                      disabled={assetActionLoading}
                      error={editError}
                      form={editForm}
                      formLabel="Edit Asset form fields"
                      onChange={setEditForm}
                      onSubmit={saveAsset}
                    />
                  </>
                ) : (
                  <>
                    <VpwSectionHeader
                      description="Open edit mode to update the selected asset context."
                      eyebrow="Context editor"
                      title="Asset editor"
                      actions={
                        <Button
                          onClick={() => startEditAsset(selectedAsset)}
                          type="button"
                          variant="outline"
                        >
                          Edit context
                        </Button>
                      }
                    />
                    <VpwStatusBanner title="Context ready" tone="info">
                      Asset edits and recalculation use the existing Workbench
                      asset APIs.
                    </VpwStatusBanner>
                  </>
                )}
              </VpwPanel>
            </VpwGrid>

            <VpwPanel className="space-y-4 p-5">
              <VpwSectionHeader
                actions={
                  <Button asChild variant="outline">
                    <a href={assetFindingsHref(selectedAsset)}>Open findings</a>
                  </Button>
                }
                description="Findings returned by the existing project findings API for this asset."
                eyebrow="Linked findings"
                title="Findings for asset"
              />
              {assetFindingsError ? (
                <VpwStatusBanner
                  title="Asset findings unavailable"
                  tone="critical"
                >
                  {assetFindingsError}
                </VpwStatusBanner>
              ) : null}
              {assetFindingsLoading ? <VpwSkeletonStack rows={4} /> : null}
              {!assetFindingsLoading && assetFindings.length === 0 ? (
                <VpwEmptyState
                  icon={<Database aria-hidden="true" />}
                  title={`No findings for ${selectedAsset.name}`}
                  description="Import occurrence data that references this asset."
                />
              ) : null}
              {assetFindings.length > 0 ? (
                <VpwDataTable
                  caption="Asset findings table"
                  columns={findingColumns}
                  data={assetFindings}
                  density="compact"
                  getRowKey={(finding) => finding.id}
                />
              ) : null}
            </VpwPanel>
          </VpwSection>
        ) : null}
      </VpwPageContainer>
    </ProductAppShell>
  )
}

export const Route = createFileRoute("/_layout/assets")({
  component: AssetsPage,
})
