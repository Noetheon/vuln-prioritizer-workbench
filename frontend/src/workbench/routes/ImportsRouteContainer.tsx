import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useLocation, useNavigate, useParams } from "@/lib/router"
import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react"
import {
  type AnalysisRunPublic,
  type AnalysisRunSummaryPublic,
  type ImportParseErrorPublic,
  ImportsService,
  RunsService,
} from "../../api-client"
import { ImportsWorkbench } from "../../components/imports/ImportsWorkbench"
import {
  analysisRunIdFromError,
  apiErrorMessage,
  parseErrorsFromError,
} from "../../lib/app-errors"
import {
  defaultImportWizardState,
  type ImportFormat,
  type ImportUploadFormData,
  type ImportWizardState,
  withDemoProviderSnapshot,
} from "../../lib/app-defaults"
import { buildImportUploadFormData } from "../import-upload-payload"
import {
  importInputTypeFromSearch,
  importRunRouteIdNeedsCanonicalRedirect,
  importsRouteUrlSearch,
  resolveImportRunRouteId,
  selectedImportRunIdFromSearch,
} from "../import-route-search"
import { selectedProjectRouteSearch } from "../selected-project-search"
import { useWorkbenchContext } from "../WorkbenchContext"
import { useProjectRunsQuery, useRunDetailQuery } from "../useWorkbenchQueries"
import {
  invalidateProjectScopedWorkbenchQueries,
  workbenchQueryKeys,
} from "../workbench-query-keys"
import {
  isImportInputType,
  supportedImportFormats,
} from "@/lib/import-format-metadata"

const TERMINAL_RUN_STATUSES = new Set([
  "cancelled",
  "completed",
  "completed_with_errors",
  "failed",
  "succeeded",
])

export function ImportsRouteContainer() {
  const location = useLocation()
  const navigate = useNavigate()
  const params = useParams<{ importsView?: string; runId?: string }>()
  const queryClient = useQueryClient()
  const {
    capabilities,
    capabilitiesError,
    capabilitiesLoading,
    projectListLoading,
    projectListError,
    projects,
    providerStatus,
    refreshProjects,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const supportedFormats = useMemo(
    () => supportedImportFormats(capabilities),
    [capabilities],
  )
  const [importWizard, setImportWizard] = useState<ImportWizardState>(
    defaultImportWizardState,
  )
  const [importError, setImportError] = useState("")
  const [failedImportRunId, setFailedImportRunId] = useState("")
  const [importRun, setImportRun] = useState<AnalysisRunPublic | null>(null)
  const [importRunSummary, setImportRunSummary] =
    useState<AnalysisRunSummaryPublic | null>(null)
  const [importParseErrors, setImportParseErrors] = useState<
    ImportParseErrorPublic[]
  >([])
  const [selectedRunId, setSelectedRunId] = useState("")
  const [pendingSelectableRunId, setPendingSelectableRunId] = useState("")
  const [refreshedTerminalRun, setRefreshedTerminalRun] = useState("")
  const routeRunId = params.importsView === "run" ? (params.runId ?? "") : ""
  const legacyRouteRunId =
    params.importsView || routeRunId
      ? ""
      : selectedImportRunIdFromSearch(location.searchStr)
  const importsView =
    params.importsView === "new" ||
    params.importsView === "run" ||
    params.importsView === "formats"
      ? params.importsView
      : "home"
  const projectRunsQuery = useProjectRunsQuery(selectedProjectId, true)
  const projectRuns = projectRunsQuery.data?.data ?? []
  const projectRunIds = projectRuns.map((run) => run.id)
  const routeSelectableRunId = resolveImportRunRouteId(
    routeRunId,
    projectRunIds,
  )
  const routeRunResolutionPending = Boolean(
    routeRunId &&
      !routeSelectableRunId &&
      (projectListLoading ||
        !selectedProjectId ||
        projectRunsQuery.isLoading ||
        projectRunsQuery.isFetching),
  )
  const routeRunResolutionUnavailable = Boolean(
    routeRunId && !routeSelectableRunId && !routeRunResolutionPending,
  )
  const runDetailQuery = useRunDetailQuery(
    selectedRunId,
    Boolean(selectedRunId),
  )
  const importMutation = useMutation({
    mutationFn: ({
      body,
      projectId,
    }: {
      body: ImportUploadFormData
      projectId: string
    }) =>
      ImportsService.importProjectUpload({
        bodyImportsImportProjectUpload: body,
        project_id: projectId,
      }),
  })

  const selectRunId = useCallback((nextRunId: string) => {
    setSelectedRunId(nextRunId)
  }, [])

  useEffect(() => {
    if (!routeRunId) {
      return
    }
    if (!routeSelectableRunId) {
      if (!routeRunResolutionPending && selectedRunId) {
        selectRunId("")
      }
      return
    }
    if (selectedRunId === routeSelectableRunId) {
      return
    }
    selectRunId(routeSelectableRunId)
  }, [
    routeRunId,
    routeRunResolutionPending,
    routeSelectableRunId,
    selectRunId,
    selectedRunId,
  ])

  useEffect(() => {
    if (
      !importRunRouteIdNeedsCanonicalRedirect(routeRunId, routeSelectableRunId)
    ) {
      return
    }
    void navigate({
      params: { runId: routeSelectableRunId },
      replace: true,
      search: () => importsRouteUrlSearch(location.searchStr),
      to: "/imports/runs/$runId",
    })
  }, [location.searchStr, navigate, routeRunId, routeSelectableRunId])

  useEffect(() => {
    if (!legacyRouteRunId) return
    void navigate({
      params: { runId: legacyRouteRunId },
      replace: true,
      search: () => importsRouteUrlSearch(location.searchStr),
      to: "/imports/runs/$runId",
    })
  }, [legacyRouteRunId, location.searchStr, navigate])

  useEffect(() => {
    if (importsView !== "new") return
    const inputType = importInputTypeFromSearch(location.searchStr)
    if (
      !isImportInputType(supportedFormats, inputType) ||
      importWizard.inputType === inputType
    ) {
      return
    }
    setImportWizard((state) => ({ ...state, inputType }))
  }, [importWizard.inputType, importsView, location.searchStr, supportedFormats])

  useEffect(() => {
    if (
      pendingSelectableRunId &&
      projectRuns.some((run) => run.id === pendingSelectableRunId)
    ) {
      setPendingSelectableRunId("")
    }
  }, [pendingSelectableRunId, projectRuns])

  async function refreshProjectRuns(preferredRunId?: string) {
    if (!selectedProjectId) {
      selectRunId("")
      return
    }
    if (preferredRunId) {
      setPendingSelectableRunId(preferredRunId)
      selectRunId(preferredRunId)
    }
    await queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectRuns(selectedProjectId),
    })
    if (preferredRunId) {
      await queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.runDetail(preferredRunId),
      })
    }
  }

  useEffect(() => {
    const runStatus = runDetailQuery.data?.run.status
    if (
      !selectedProjectId ||
      !selectedRunId ||
      !runStatus ||
      !TERMINAL_RUN_STATUSES.has(runStatus)
    ) {
      return
    }
    const refreshKey = `${selectedRunId}:${runStatus}`
    if (refreshKey === refreshedTerminalRun) {
      return
    }
    setRefreshedTerminalRun(refreshKey)
    setImportRun(runDetailQuery.data?.run ?? null)
    setImportRunSummary(runDetailQuery.data?.summary ?? null)
    setImportParseErrors(runDetailQuery.data?.summary.parse_errors ?? [])
    void Promise.all([
      refreshProjects(selectedProjectId),
      queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.projectRuns(selectedProjectId),
      }),
      invalidateProjectScopedWorkbenchQueries(queryClient, selectedProjectId),
    ])
  }, [
    queryClient,
    refreshedTerminalRun,
    refreshProjects,
    runDetailQuery.data?.run,
    runDetailQuery.data?.summary,
    selectedProjectId,
    selectedRunId,
  ])

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
    setFailedImportRunId("")
    setImportRun(null)
    setImportRunSummary(null)
    setImportParseErrors([])
    if (capabilitiesError || supportedFormats.length === 0) {
      setImportError(
        capabilitiesError ||
          "Workbench capabilities unavailable. Imports are disabled until runtime metadata loads.",
      )
      return
    }
    if (!importProjectId) {
      setImportError("Select or create a project before uploading.")
      return
    }
    if (!selectedFile) {
      setImportError("Choose an import file before uploading.")
      return
    }
    if (!isImportInputType(supportedFormats, importWizard.inputType)) {
      setImportError("Select an input type before uploading.")
      return
    }

    try {
      setSelectedProjectId(importProjectId)
      const uploadFormData: ImportUploadFormData = buildImportUploadFormData({
        importWizard,
        selectedAssetContextFile,
        selectedFile,
        selectedVexFile,
      })
      const run = await importMutation.mutateAsync({
        body: uploadFormData,
        projectId: importProjectId,
      })
      setImportRun(run)
      const summary = await RunsService.readRunSummary({ run_id: run.id })
      setImportRunSummary(summary)
      setImportParseErrors(summary.parse_errors ?? [])
      setFailedImportRunId("")
      setPendingSelectableRunId(run.id)
      selectRunId(run.id)
      void navigate({
        params: { runId: run.id },
        search: selectedProjectRouteSearch(importProjectId),
        to: "/imports/runs/$runId",
      })
      await refreshProjects(importProjectId)
      await refreshProjectRuns(run.id)
      await invalidateProjectScopedWorkbenchQueries(
        queryClient,
        importProjectId,
      )
    } catch (caught) {
      setImportError(apiErrorMessage("Import upload failed", caught))
      const runId = analysisRunIdFromError(caught)
      const parseErrors = parseErrorsFromError(caught)
      setFailedImportRunId(runId ?? "")
      setImportParseErrors(parseErrors)
      if (runId) {
        setPendingSelectableRunId(runId)
        selectRunId(runId)
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
      await invalidateProjectScopedWorkbenchQueries(
        queryClient,
        importProjectId,
      )
    }
  }

  function handleProjectChange(projectId: string) {
    setSelectedProjectId(projectId)
    selectRunId("")
  }

  return (
    <ImportsWorkbench
      failedImportRunId={failedImportRunId}
      importError={importError}
      importLoading={importMutation.isPending}
      importParseErrors={importParseErrors}
      importRun={importRun}
      importRunSummary={importRunSummary}
      importWizard={importWizard}
      capabilitiesError={capabilitiesError}
      capabilitiesLoading={capabilitiesLoading}
      onAssetContextFileChange={(file) =>
        setImportWizard((state) => ({
          ...state,
          assetContextFile: file,
        }))
      }
      onFileChange={(file) => setImportWizard((state) => ({ ...state, file }))}
      onInputTypeChange={(value) =>
        setImportWizard((state) => ({
          ...state,
          inputType: isImportInputType(supportedFormats, value)
            ? (value as ImportFormat)
            : "",
        }))
      }
      onLockedProviderDataChange={(value) =>
        setImportWizard((state) => ({ ...state, lockedProviderData: value }))
      }
      onProviderSnapshotFileChange={(value) =>
        setImportWizard((state) => ({ ...state, providerSnapshotFile: value }))
      }
      onUseDemoProviderSnapshot={() =>
        setImportWizard((state) => withDemoProviderSnapshot(state))
      }
      onProjectChange={handleProjectChange}
      onRefreshRuns={() => void refreshProjectRuns(selectedRunId)}
      onSelectRun={selectRunId}
      onSubmit={submitImport}
      onAttackMappingFileChange={(value) =>
        setImportWizard((state) => ({ ...state, attackMappingFile: value }))
      }
      onAttackSourceChange={(value) =>
        setImportWizard((state) => ({
          ...state,
          attackSource: value as ImportWizardState["attackSource"],
        }))
      }
      onAttackTechniqueMetadataFileChange={(value) =>
        setImportWizard((state) => ({
          ...state,
          attackTechniqueMetadataFile: value,
        }))
      }
      onVexFileChange={(file) =>
        setImportWizard((state) => ({ ...state, vexFile: file }))
      }
      projectListLoading={projectListLoading}
      projectListError={projectListError}
      projectRuns={projectRuns}
      projects={projects}
      providerStatus={providerStatus}
      runDetailError={
        routeRunResolutionUnavailable
          ? "Run detail unavailable: unknown import run."
          : runDetailQuery.isError
            ? apiErrorMessage("Run detail unavailable", runDetailQuery.error)
            : ""
      }
      runDetailLoading={
        routeRunResolutionPending ||
        runDetailQuery.isLoading ||
        runDetailQuery.isFetching
      }
      runsError={
        projectRunsQuery.isError
          ? apiErrorMessage("Import runs unavailable", projectRunsQuery.error)
          : ""
      }
      runsLoading={projectRunsQuery.isLoading || projectRunsQuery.isFetching}
      selectedProject={selectedProject}
      selectedProjectId={selectedProjectId}
      selectedRun={runDetailQuery.data?.run ?? null}
      selectedRunId={selectedRunId}
      selectedRunSummary={runDetailQuery.data?.summary ?? null}
      attackSources={capabilities?.attack_sources ?? []}
      supportedFormats={supportedFormats}
      view={importsView}
    />
  )
}
