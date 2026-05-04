import { useNavigate } from "@tanstack/react-router"
import { type FormEvent, useEffect, useMemo, useState } from "react"

import {
  ApiError,
  type AssetPublic,
  AssetsService,
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
import {
  apiErrorMessage,
  assetFormFromAsset,
  assetRequestBody,
  assetUpdateBody,
  buildServiceRollups,
  emptyAssetForm,
  highestFindingPriority,
  matchesAsset,
  summarizeAssets,
  validateAssetForm,
} from "./asset-model"

export function useAssetsRouteState() {
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
  const [createForm, setCreateForm] = useState(emptyAssetForm)
  const [createError, setCreateError] = useState("")
  const [editForm, setEditForm] = useState(emptyAssetForm)
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

  function selectProject(projectId: string) {
    setSelectedProjectId(projectId)
    setEditingAssetId("")
    setAssetMessage("")
  }

  function clearAssetFilters() {
    setAssetOwnerFilter("")
    setAssetServiceFilter("")
  }

  const assetSummary = summarizeAssets(assets)
  const serviceRollups = buildServiceRollups(assets)
  const selectedHighestPriority = highestFindingPriority(assetFindings)
  const activeProjectLabel =
    selectedProject?.name ?? (projectLoading ? "Loading" : "No project")
  const projectSelectDisabled = projectLoading || projects.length === 0

  return {
    activeProjectLabel,
    assetActionLoading,
    assetContextFile,
    assetFindings,
    assetFindingsError,
    assetFindingsLoading,
    assetMessage,
    assetOwnerFilter,
    assets,
    assetsError,
    assetsLoading,
    assetServiceFilter,
    assetSummary,
    clearAssetFilters,
    createAsset,
    createError,
    createForm,
    currentUser,
    editError,
    editForm,
    editingAssetId,
    importAssetContext,
    projectLoading,
    projects,
    projectSelectDisabled,
    providerStatus,
    recalculateAsset,
    refreshAssets,
    saveAsset,
    selectProject,
    selectedAsset,
    selectedAssetId,
    selectedHighestPriority,
    selectedProject,
    selectedProjectId,
    serviceRollups,
    setAssetContextFile,
    setAssetOwnerFilter,
    setAssetServiceFilter,
    setCreateForm,
    setEditForm,
    setSelectedAssetId,
    startEditAsset,
    status,
    statusError,
  }
}
