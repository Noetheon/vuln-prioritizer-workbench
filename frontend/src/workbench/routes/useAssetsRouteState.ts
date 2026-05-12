import { useMutation, useQueryClient } from "@tanstack/react-query"
import {
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react"

import {
  type AssetPublic,
  AssetsService,
} from "../../api-client"
import type { AssetsWorkbenchProps } from "../../components/assets"
import {
  apiErrorMessage,
  assetFormFromAsset,
  assetRequestBody,
  assetUpdateBody,
  buildServiceRollups,
  emptyAssetForm,
  highestFindingPriority,
  summarizeAssets,
  validateAssetForm,
} from "../../components/assets/asset-model"
import { useWorkbenchContext } from "../WorkbenchContext"
import {
  useAssetFindingsQuery,
  useProjectAssetsQuery,
} from "../useWorkbenchQueries"
import { invalidateProjectScopedWorkbenchQueries } from "../workbench-query-keys"

export function useAssetsRouteState(): AssetsWorkbenchProps {
  const queryClient = useQueryClient()
  const {
    projectListLoading,
    projects,
    providerStatus,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const [assetOwnerFilter, setAssetOwnerFilter] = useState("")
  const [assetServiceFilter, setAssetServiceFilter] = useState("")
  const [assetMessage, setAssetMessage] = useState("")
  const [assetsError, setAssetsError] = useState("")
  const [assetContextFile, setAssetContextFile] = useState<File | null>(null)
  const [createForm, setCreateForm] = useState(emptyAssetForm)
  const [createError, setCreateError] = useState("")
  const [editForm, setEditForm] = useState(emptyAssetForm)
  const [editError, setEditError] = useState("")
  const [editingAssetId, setEditingAssetId] = useState("")
  const [selectedAssetId, setSelectedAssetId] = useState("")
  const previousProjectId = useRef(selectedProjectId)
  const assetsQuery = useProjectAssetsQuery({
    owner: assetOwnerFilter,
    projectId: selectedProjectId,
    service: assetServiceFilter,
  })
  const assets = assetsQuery.data?.data ?? []
  const selectedAsset = useMemo(
    () => assets.find((asset) => asset.id === selectedAssetId) ?? null,
    [assets, selectedAssetId],
  )
  const assetFindingsQuery = useAssetFindingsQuery({
    asset: selectedAsset,
    projectId: selectedProjectId,
  })
  const createAssetMutation = useMutation({
    mutationFn: ({
      assetCreate,
      projectId,
    }: {
      assetCreate: ReturnType<typeof assetRequestBody>
      projectId: string
    }) =>
      AssetsService.createProjectAsset({
        assetCreate,
        project_id: projectId,
      }),
  })
  const updateAssetMutation = useMutation({
    mutationFn: ({
      asset,
      assetId,
    }: {
      asset: ReturnType<typeof assetUpdateBody>
      assetId: string
    }) =>
      AssetsService.updateAsset({
        asset_id: assetId,
        assetUpdate: asset,
      }),
  })
  const recalculateAssetMutation = useMutation({
    mutationFn: (assetId: string) =>
      AssetsService.recalculateAsset({ asset_id: assetId }),
  })
  const importAssetContextMutation = useMutation({
    mutationFn: ({
      assetContextFile,
      projectId,
    }: {
      assetContextFile: File
      projectId: string
    }) =>
      AssetsService.importProjectAssets({
        bodyAssetsImportProjectAssets: {
          asset_context_file: assetContextFile,
        },
        project_id: projectId,
      }),
  })

  const refreshAssets = useCallback(
    async (preferredAssetId?: string) => {
      if (preferredAssetId) {
        setSelectedAssetId(preferredAssetId)
      }
      if (!selectedProjectId) {
        setSelectedAssetId("")
        return
      }
      await invalidateProjectScopedWorkbenchQueries(queryClient, selectedProjectId)
    },
    [queryClient, selectedProjectId],
  )

  useEffect(() => {
    if (previousProjectId.current === selectedProjectId) {
      return
    }
    previousProjectId.current = selectedProjectId
    setSelectedAssetId("")
    setEditingAssetId("")
    setAssetMessage("")
    setAssetsError("")
  }, [selectedProjectId])

  useEffect(() => {
    setSelectedAssetId((currentAssetId) =>
      assets.some((asset) => asset.id === currentAssetId)
        ? currentAssetId
        : (assets[0]?.id ?? ""),
    )
  }, [assets])

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

    try {
      const asset = await createAssetMutation.mutateAsync({
        assetCreate: assetRequestBody(createForm),
        projectId: selectedProjectId,
      })
      setCreateForm(emptyAssetForm)
      setAssetMessage(`Asset ${asset.name} created.`)
      await refreshAssets(asset.id)
    } catch (caught) {
      setAssetsError(apiErrorMessage("Asset create failed", caught))
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

    try {
      const asset = await updateAssetMutation.mutateAsync({
        asset: assetUpdateBody(editForm),
        assetId: editingAssetId,
      })
      setEditingAssetId("")
      setAssetMessage(`Asset ${asset.name} updated.`)
      await refreshAssets(asset.id)
    } catch (caught) {
      setAssetsError(apiErrorMessage("Asset update failed", caught))
    }
  }

  async function recalculateAsset(asset: AssetPublic) {
    setAssetsError("")
    setAssetMessage("")
    try {
      const result = await recalculateAssetMutation.mutateAsync(asset.id)
      setAssetMessage(
        `Recalculated ${result.recalculated_findings} finding(s) for ${asset.name}.`,
      )
      await refreshAssets(asset.id)
    } catch (caught) {
      setAssetsError(apiErrorMessage("Asset recalculation failed", caught))
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

    try {
      const result = await importAssetContextMutation.mutateAsync({
        assetContextFile,
        projectId: selectedProjectId,
      })
      setAssetContextFile(null)
      setAssetMessage(
        `Imported ${result.imported_assets} asset(s); ${result.rescore_needed_findings} finding(s) need recalculation.`,
      )
      await refreshAssets(selectedAssetId)
    } catch (caught) {
      setAssetsError(apiErrorMessage("Asset context import failed", caught))
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

  const assetActionLoading =
    createAssetMutation.isPending ||
    updateAssetMutation.isPending ||
    recalculateAssetMutation.isPending ||
    importAssetContextMutation.isPending
  const assetQueryError = assetsQuery.isError
    ? apiErrorMessage("Assets unavailable", assetsQuery.error)
    : ""
  const assetFindingsError = assetFindingsQuery.isError
    ? apiErrorMessage("Asset findings unavailable", assetFindingsQuery.error)
    : ""
  const assetFindings = assetFindingsQuery.data ?? []

  return {
    activeProjectLabel:
      selectedProject?.name ?? (projectListLoading ? "Loading" : "No project"),
    assetActionLoading,
    assetContextFile,
    assetFindings,
    assetFindingsError,
    assetFindingsLoading:
      assetFindingsQuery.isLoading || assetFindingsQuery.isFetching,
    assetMessage,
    assetOwnerFilter,
    assets,
    assetsError: assetsError || assetQueryError,
    assetsLoading: assetsQuery.isLoading || assetsQuery.isFetching,
    assetServiceFilter,
    assetSummary: summarizeAssets(assets),
    clearAssetFilters,
    createAsset,
    createError,
    createForm,
    editError,
    editForm,
    editingAssetId,
    importAssetContext,
    projectLoading: projectListLoading,
    projects,
    projectSelectDisabled: projectListLoading || projects.length === 0,
    providerStatus,
    recalculateAsset,
    refreshAssets,
    saveAsset,
    selectProject,
    selectedAsset,
    selectedAssetId,
    selectedHighestPriority: highestFindingPriority(assetFindings),
    selectedProject,
    selectedProjectId,
    serviceRollups: buildServiceRollups(assets),
    setAssetContextFile,
    setAssetOwnerFilter,
    setAssetServiceFilter,
    setCreateForm,
    setEditForm,
    setSelectedAssetId,
    startEditAsset,
  }
}
