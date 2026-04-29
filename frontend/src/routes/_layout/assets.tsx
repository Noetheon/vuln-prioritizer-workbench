import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import {
  Activity,
  Database,
  FileArchive,
  FileInput,
  FolderKanban,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  RefreshCw,
  Settings,
  ShieldCheck,
} from "lucide-react"
import { type FormEvent, useEffect, useMemo, useState } from "react"

import { clearAccessToken } from "../../auth"
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
} from "../../client"

const navigation = [
  { label: "Dashboard", icon: LayoutDashboard, to: "/" },
  { label: "Projects", icon: FolderKanban, to: "/projects" },
  { label: "Imports", icon: FileInput, to: "/imports" },
  { label: "Findings", icon: ListChecks, to: "/findings" },
  { label: "Assets", icon: ShieldCheck, to: "/assets" },
  { label: "Providers", icon: Database, to: "/providers" },
  { label: "Reports", icon: FileArchive, to: "/reports" },
  { label: "Settings", icon: Settings, to: "/settings" },
] as const

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

function currentUserLabel(user: UserPublic | null) {
  return user?.email ?? "Local workspace"
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
  return (
    <form
      aria-label={formLabel}
      className="project-edit-form"
      onSubmit={onSubmit}
    >
      <label>
        <span>Asset key</span>
        <input
          aria-label={
            formLabel.includes("Edit") ? "Edit asset key" : "Asset key"
          }
          maxLength={255}
          onChange={(event) =>
            onChange({ ...form, asset_key: event.target.value })
          }
          value={form.asset_key}
        />
      </label>
      <label>
        <span>Asset name</span>
        <input
          aria-label={
            formLabel.includes("Edit") ? "Edit asset name" : "Asset name"
          }
          maxLength={255}
          onChange={(event) => onChange({ ...form, name: event.target.value })}
          value={form.name}
        />
      </label>
      <label>
        <span>Owner</span>
        <input
          aria-label={formLabel.includes("Edit") ? "Edit owner" : "Owner"}
          maxLength={255}
          onChange={(event) => onChange({ ...form, owner: event.target.value })}
          value={form.owner}
        />
      </label>
      <label>
        <span>Business service</span>
        <input
          aria-label={
            formLabel.includes("Edit")
              ? "Edit business service"
              : "Business service"
          }
          maxLength={255}
          onChange={(event) =>
            onChange({ ...form, business_service: event.target.value })
          }
          value={form.business_service}
        />
      </label>
      <label>
        <span>Target ref</span>
        <input
          aria-label={
            formLabel.includes("Edit") ? "Edit target ref" : "Target ref"
          }
          maxLength={512}
          onChange={(event) =>
            onChange({ ...form, target_ref: event.target.value })
          }
          value={form.target_ref}
        />
      </label>
      <label>
        <span>Criticality</span>
        <select
          aria-label={
            formLabel.includes("Edit") ? "Edit criticality" : "Criticality"
          }
          onChange={(event) =>
            onChange({
              ...form,
              criticality: event.target.value as AssetCriticality,
            })
          }
          value={form.criticality}
        >
          {criticalityOptions.map((option) => (
            <option key={option} value={option}>
              {labelize(option)}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Environment</span>
        <select
          aria-label={
            formLabel.includes("Edit") ? "Edit environment" : "Environment"
          }
          onChange={(event) =>
            onChange({
              ...form,
              environment: event.target.value as AssetEnvironment,
            })
          }
          value={form.environment}
        >
          {environmentOptions.map((option) => (
            <option key={option} value={option}>
              {labelize(option)}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Exposure</span>
        <select
          aria-label={formLabel.includes("Edit") ? "Edit exposure" : "Exposure"}
          onChange={(event) =>
            onChange({ ...form, exposure: event.target.value as AssetExposure })
          }
          value={form.exposure}
        >
          {exposureOptions.map((option) => (
            <option key={option} value={option}>
              {labelize(option)}
            </option>
          ))}
        </select>
      </label>
      {error ? <p className="form-error">{error}</p> : null}
      <button className="primary-action" disabled={disabled} type="submit">
        {buttonLabel}
      </button>
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
        projectId: selectedProjectId,
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
          setStatusError("Backend adapter unavailable")
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
          assetId: selectedAsset.id,
          limit: 200,
          offset: 0,
          projectId: selectedProjectId,
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
        projectId: selectedProjectId,
        requestBody: assetRequestBody(createForm),
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
        assetId: editingAssetId,
        requestBody: assetUpdateBody(editForm),
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
      const result = await AssetsService.recalculateAsset({ assetId: asset.id })
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
        projectId: selectedProjectId,
        formData: {
          asset_context_file: assetContextFile as unknown as string,
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
          {navigation.map((entry) => (
            <Link
              aria-current={entry.to === "/assets" ? "page" : undefined}
              className={
                entry.to === "/assets" ? "nav-item active" : "nav-item"
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
            <span className="eyebrow">Workbench Assets</span>
            <h1>Assets</h1>
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
            aria-label="Sign out"
            className="icon-button"
            onClick={signOut}
            type="button"
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

        <section className="content-grid wide-workspace">
          <div className="work-panel">
            <div className="panel-header">
              <div>
                <h2>Asset Context</h2>
                <span>Business and exposure context for ranking</span>
              </div>
              <button
                aria-label="Refresh assets"
                className="icon-button"
                disabled={assetsLoading}
                onClick={() => void refreshAssets(selectedAssetId)}
                type="button"
              >
                <Activity aria-hidden="true" size={18} />
              </button>
            </div>

            <section className="projects-workflow" aria-label="Assets workflow">
              <section
                className="dashboard-toolbar"
                aria-label="Assets project context"
              >
                <label className="project-selector">
                  <span>Project</span>
                  <select
                    aria-label="Assets project"
                    disabled={projectLoading || projects.length === 0}
                    onChange={(event) => {
                      setSelectedProjectId(event.target.value)
                      setEditingAssetId("")
                      setAssetMessage("")
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
                <div className="project-context">
                  <span>Selected project</span>
                  <strong>
                    {selectedProject?.name ??
                      (projectLoading ? "Loading" : "No project selected")}
                  </strong>
                </div>
                <label className="project-selector">
                  <span>Owner</span>
                  <input
                    aria-label="Asset owner filter"
                    onChange={(event) =>
                      setAssetOwnerFilter(event.target.value)
                    }
                    placeholder="Filter owner"
                    value={assetOwnerFilter}
                  />
                </label>
                <label className="project-selector">
                  <span>Service</span>
                  <input
                    aria-label="Asset service filter"
                    onChange={(event) =>
                      setAssetServiceFilter(event.target.value)
                    }
                    placeholder="Filter service"
                    value={assetServiceFilter}
                  />
                </label>
                <button
                  className="secondary-action"
                  disabled={!assetOwnerFilter && !assetServiceFilter}
                  onClick={() => {
                    setAssetOwnerFilter("")
                    setAssetServiceFilter("")
                  }}
                  type="button"
                >
                  Clear Filters
                </button>
              </section>

              <section
                className="project-form-panel"
                aria-label="Import Asset Context form"
              >
                <h3>Import Asset Context</h3>
                <form
                  aria-label="Import Asset Context form fields"
                  className="project-edit-form"
                  onSubmit={importAssetContext}
                >
                  <label>
                    <span>Asset context CSV</span>
                    <input
                      accept=".csv,text/csv"
                      aria-label="Asset context CSV"
                      onChange={(event) =>
                        setAssetContextFile(event.target.files?.[0] ?? null)
                      }
                      type="file"
                    />
                  </label>
                  <button
                    className="primary-action"
                    disabled={
                      assetActionLoading ||
                      projects.length === 0 ||
                      !assetContextFile
                    }
                    type="submit"
                  >
                    <FileInput aria-hidden="true" size={16} />
                    <span>Import Context</span>
                  </button>
                </form>
              </section>

              <section
                className="project-form-panel"
                aria-label="Create Asset form"
              >
                <h3>Create Asset</h3>
                <AssetForm
                  buttonLabel="Create Asset"
                  disabled={assetActionLoading || projects.length === 0}
                  error={createError}
                  form={createForm}
                  formLabel="Create Asset form fields"
                  onChange={setCreateForm}
                  onSubmit={createAsset}
                />
              </section>

              {assetsError ? (
                <p className="dashboard-alert" role="alert">
                  {assetsError}
                </p>
              ) : null}
              {assetMessage ? (
                <p className="dashboard-state" role="status">
                  {assetMessage}
                </p>
              ) : null}
              {assetsLoading ? (
                <p className="dashboard-state" role="status">
                  Loading assets
                </p>
              ) : null}

              {projects.length === 0 && !projectLoading ? (
                <section
                  className="dashboard-empty"
                  aria-label="Assets no project empty state"
                >
                  <h3>No projects yet</h3>
                  <p>Create a project before managing assets.</p>
                  <Link className="primary-action" to="/projects">
                    Projects
                  </Link>
                </section>
              ) : null}

              {!assetsLoading && selectedProject && assets.length === 0 ? (
                <section
                  className="dashboard-empty"
                  aria-label="Assets empty state"
                >
                  <h3>No assets in {selectedProject.name}</h3>
                  <p>
                    Add the first asset to attach owner, service, and exposure
                    context.
                  </p>
                </section>
              ) : null}

              {assets.length > 0 ? (
                <section
                  className="project-list-panel"
                  aria-label="Assets list"
                >
                  <div className="table-wrap findings-table-wrap">
                    <table aria-label="Assets table">
                      <thead>
                        <tr>
                          <th>Asset</th>
                          <th>Owner</th>
                          <th>Service</th>
                          <th>Criticality</th>
                          <th>Environment</th>
                          <th>Exposure</th>
                          <th>Findings</th>
                          <th>Status</th>
                          <th>Updated</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {assets.map((asset) => (
                          <tr key={asset.id}>
                            <td>
                              <button
                                aria-current={
                                  selectedAssetId === asset.id
                                    ? "true"
                                    : undefined
                                }
                                className="project-list-item"
                                onClick={() => setSelectedAssetId(asset.id)}
                                type="button"
                              >
                                <strong>{asset.name}</strong>
                                <span>{asset.asset_key}</span>
                              </button>
                            </td>
                            <td>{optionalText(asset.owner)}</td>
                            <td>{optionalText(asset.business_service)}</td>
                            <td>{labelize(asset.criticality)}</td>
                            <td>{labelize(asset.environment)}</td>
                            <td>{labelize(asset.exposure)}</td>
                            <td>{asset.finding_count ?? 0}</td>
                            <td>
                              <span className="status-pill">
                                {asset.rescore_needed
                                  ? "Re-score needed"
                                  : "Current"}
                              </span>
                            </td>
                            <td>{formatDateTime(asset.updated_at)}</td>
                            <td>
                              <div className="empty-actions">
                                <a
                                  className="secondary-action"
                                  href={assetFindingsHref(asset)}
                                >
                                  Findings
                                </a>
                                <button
                                  className="secondary-action"
                                  onClick={() => {
                                    setSelectedAssetId(asset.id)
                                    startEditAsset(asset)
                                  }}
                                  type="button"
                                >
                                  Edit
                                </button>
                                <button
                                  aria-label={`Recalculate ${asset.name}`}
                                  className="secondary-action"
                                  disabled={
                                    assetActionLoading ||
                                    (asset.finding_count ?? 0) === 0
                                  }
                                  onClick={() => void recalculateAsset(asset)}
                                  type="button"
                                >
                                  <RefreshCw aria-hidden="true" size={16} />
                                  <span>Recalculate</span>
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ) : null}

              {selectedAsset ? (
                <section className="project-detail" aria-label="Asset detail">
                  <div className="project-detail-header">
                    <div>
                      <span>Selected asset</span>
                      <h3>{selectedAsset.name}</h3>
                      <p>{selectedAsset.asset_key}</p>
                    </div>
                    <button
                      className="secondary-action"
                      onClick={() => startEditAsset(selectedAsset)}
                      type="button"
                    >
                      Edit Asset
                    </button>
                    <button
                      className="secondary-action"
                      disabled={
                        assetActionLoading ||
                        (selectedAsset.finding_count ?? 0) === 0
                      }
                      onClick={() => void recalculateAsset(selectedAsset)}
                      type="button"
                    >
                      <RefreshCw aria-hidden="true" size={16} />
                      <span>Recalculate</span>
                    </button>
                  </div>
                  <dl className="project-meta">
                    <div>
                      <dt>Findings</dt>
                      <dd>{selectedAsset.finding_count ?? 0}</dd>
                    </div>
                    <div>
                      <dt>Score status</dt>
                      <dd>
                        {selectedAsset.rescore_needed
                          ? "Re-score needed"
                          : "Current"}
                      </dd>
                    </div>
                    <div>
                      <dt>Owner</dt>
                      <dd>{optionalText(selectedAsset.owner)}</dd>
                    </div>
                    <div>
                      <dt>Business service</dt>
                      <dd>{optionalText(selectedAsset.business_service)}</dd>
                    </div>
                    <div>
                      <dt>Target ref</dt>
                      <dd>{optionalText(selectedAsset.target_ref)}</dd>
                    </div>
                    <div>
                      <dt>Criticality</dt>
                      <dd>{labelize(selectedAsset.criticality)}</dd>
                    </div>
                    <div>
                      <dt>Environment</dt>
                      <dd>{labelize(selectedAsset.environment)}</dd>
                    </div>
                    <div>
                      <dt>Exposure</dt>
                      <dd>{labelize(selectedAsset.exposure)}</dd>
                    </div>
                  </dl>

                  {editingAssetId === selectedAsset.id ? (
                    <AssetForm
                      buttonLabel="Save Asset"
                      disabled={assetActionLoading}
                      error={editError}
                      form={editForm}
                      formLabel="Edit Asset form fields"
                      onChange={setEditForm}
                      onSubmit={saveAsset}
                    />
                  ) : null}

                  <section
                    className="runs-browser"
                    aria-label="Findings for selected asset"
                  >
                    <div className="runs-section-header">
                      <div>
                        <h3>Findings for Asset</h3>
                        <span>{selectedAsset.name}</span>
                      </div>
                      <a
                        className="secondary-action"
                        href={assetFindingsHref(selectedAsset)}
                      >
                        Findings
                      </a>
                    </div>
                    {assetFindingsError ? (
                      <p className="dashboard-alert" role="alert">
                        {assetFindingsError}
                      </p>
                    ) : null}
                    {assetFindingsLoading ? (
                      <p className="dashboard-state" role="status">
                        Loading asset findings
                      </p>
                    ) : null}
                    {!assetFindingsLoading && assetFindings.length === 0 ? (
                      <section
                        className="dashboard-empty compact-empty"
                        aria-label="Asset findings empty state"
                      >
                        <h3>No findings for {selectedAsset.name}</h3>
                        <p>
                          Import occurrence data that references this asset.
                        </p>
                      </section>
                    ) : null}
                    {assetFindings.length > 0 ? (
                      <div className="table-wrap findings-table-wrap">
                        <table aria-label="Asset findings table">
                          <thead>
                            <tr>
                              <th>Priority</th>
                              <th>CVE</th>
                              <th>Component</th>
                              <th>Asset</th>
                              <th>Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {assetFindings.map((finding) => (
                              <tr key={finding.id}>
                                <td>
                                  <span
                                    className={`severity ${finding.priority ?? "low"}`}
                                  >
                                    {labelize(finding.priority)}
                                  </span>
                                </td>
                                <td>
                                  <Link
                                    className="finding-cve-link"
                                    params={{ findingId: finding.id }}
                                    to="/findings/$findingId"
                                  >
                                    {finding.cve_id}
                                  </Link>
                                </td>
                                <td>{optionalText(finding.component_name)}</td>
                                <td>{findingAssetLabel(finding)}</td>
                                <td>{labelize(finding.status)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : null}
                  </section>
                </section>
              ) : null}
            </section>
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
                  <dt>Last error</dt>
                  <dd>
                    {providerStatus?.last_error ?? (statusError || "None")}
                  </dd>
                </div>
              </dl>
            </section>
          </div>
        </section>
      </main>
    </div>
  )
}

export const Route = createFileRoute("/_layout/assets")({
  component: AssetsPage,
})
