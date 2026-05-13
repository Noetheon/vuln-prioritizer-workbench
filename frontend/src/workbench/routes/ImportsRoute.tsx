import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useLocation, useNavigate } from "@/lib/router"
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
  workbenchImportFormats,
} from "../../lib/app-defaults"
import { buildImportUploadFormData } from "../import-upload-payload"
import {
  importRunUrlSearch,
  normalizeSelectedRunId,
  selectedImportRunIdFromSearch,
} from "../import-route-search"
import { searchStringFromUrlSearch } from "../selected-project-search"
import { useWorkbenchContext } from "../WorkbenchContext"
import {
  useProjectRunsQuery,
  useRunDetailQuery,
} from "../useWorkbenchQueries"
import {
  invalidateProjectScopedWorkbenchQueries,
  workbenchQueryKeys,
} from "../workbench-query-keys"

const TERMINAL_RUN_STATUSES = new Set([
  "cancelled",
  "completed",
  "completed_with_errors",
  "failed",
  "succeeded",
])

function activeSearchString(fallbackSearch: string) {
  return typeof window === "undefined" ? fallbackSearch : window.location.search
}

function ImportsRouteContainer() {
  const location = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const {
    projectListLoading,
    projectListError,
    projects,
    providerStatus,
    refreshProjects,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const [importWizard, setImportWizard] = useState<ImportWizardState>(
    defaultImportWizardState,
  )
  const [importError, setImportError] = useState("")
  const [importRun, setImportRun] = useState<AnalysisRunPublic | null>(null)
  const [importRunSummary, setImportRunSummary] =
    useState<AnalysisRunSummaryPublic | null>(null)
  const [importParseErrors, setImportParseErrors] = useState<
    ImportParseErrorPublic[]
  >([])
  const [selectedRunId, setSelectedRunId] = useState("")
  const [pendingSelectableRunId, setPendingSelectableRunId] = useState("")
  const [refreshedTerminalRun, setRefreshedTerminalRun] = useState("")
  const routeRunId = selectedImportRunIdFromSearch(location.searchStr)
  const projectRunsQuery = useProjectRunsQuery(selectedProjectId, true)
  const projectRuns = projectRunsQuery.data?.data ?? []
  const runDetailQuery = useRunDetailQuery(selectedRunId, true)
  const runIds = useMemo(() => projectRuns.map((run) => run.id), [projectRuns])
  const selectableRunIds = useMemo(
    () =>
      pendingSelectableRunId && !runIds.includes(pendingSelectableRunId)
        ? [pendingSelectableRunId, ...runIds]
        : runIds,
    [pendingSelectableRunId, runIds],
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

  const selectRunId = useCallback(
    (nextRunId: string, { replace }: { replace: boolean }) => {
      setSelectedRunId(nextRunId)
      const currentLocationSearch = activeSearchString(location.searchStr)
      const nextSearch = importRunUrlSearch(currentLocationSearch, nextRunId)
      const currentSearch = currentLocationSearch.startsWith("?")
        ? currentLocationSearch.slice(1)
        : currentLocationSearch
      if (searchStringFromUrlSearch(nextSearch) === currentSearch) {
        return
      }
      void navigate({
        replace,
        search: () => nextSearch,
      })
    },
    [location.searchStr, navigate],
  )

  useEffect(() => {
    if (projectRunsQuery.isLoading && runIds.length === 0) {
      return
    }
    const nextRunId = normalizeSelectedRunId(
      [routeRunId, selectedRunId],
      selectableRunIds,
    )
    if (nextRunId === selectedRunId && nextRunId === routeRunId) {
      return
    }
    selectRunId(nextRunId, { replace: true })
  }, [
    projectRunsQuery.isLoading,
    routeRunId,
    runIds,
    selectRunId,
    selectableRunIds,
    selectedRunId,
  ])

  useEffect(() => {
    if (pendingSelectableRunId && runIds.includes(pendingSelectableRunId)) {
      setPendingSelectableRunId("")
    }
  }, [pendingSelectableRunId, runIds])

  async function refreshProjectRuns(preferredRunId?: string) {
    if (!selectedProjectId) {
      selectRunId("", { replace: true })
      return
    }
    if (preferredRunId) {
      setPendingSelectableRunId(preferredRunId)
      selectRunId(preferredRunId, { replace: false })
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
      setPendingSelectableRunId(run.id)
      selectRunId(run.id, { replace: false })
      await refreshProjects(importProjectId)
      await refreshProjectRuns(run.id)
      await invalidateProjectScopedWorkbenchQueries(queryClient, importProjectId)
    } catch (caught) {
      setImportError(apiErrorMessage("Import upload failed", caught))
      const runId = analysisRunIdFromError(caught)
      const parseErrors = parseErrorsFromError(caught)
      setImportParseErrors(parseErrors)
      if (runId) {
        setPendingSelectableRunId(runId)
        selectRunId(runId, { replace: false })
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
      await invalidateProjectScopedWorkbenchQueries(queryClient, importProjectId)
    }
  }

  function handleProjectChange(projectId: string) {
    setSelectedProjectId(projectId)
    selectRunId("", { replace: true })
  }

  return (
    <ImportsWorkbench
      importError={importError}
      importLoading={importMutation.isPending}
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
      onSelectRun={(runId) => selectRunId(runId, { replace: false })}
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
        runDetailQuery.isError
          ? apiErrorMessage("Run detail unavailable", runDetailQuery.error)
          : ""
      }
      runDetailLoading={runDetailQuery.isLoading || runDetailQuery.isFetching}
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
      supportedFormats={workbenchImportFormats}
    />
  )
}

export function ImportsRoute() {
  return <ImportsRouteContainer />
}
