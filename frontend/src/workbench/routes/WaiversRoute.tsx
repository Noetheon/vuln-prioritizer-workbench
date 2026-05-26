import { useMutation, useQueryClient } from "@tanstack/react-query"
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react"
import { WaiversService, type WaiverPublic } from "../../api-client"
import { WaiversWorkbench } from "../../components/waivers/WaiversWorkbench"
import type { WaiverDrawerMode } from "../../components/waivers"
import { apiErrorMessage } from "../../lib/app-errors"
import {
  validateWaiverForm,
  waiverFormFromWaiver,
  type WaiverFormState,
  waiverFormDefaults,
  waiverRequestBody,
  waiverScopeLabel,
} from "../../lib/waiver-view"
import { useWorkbenchContext } from "../WorkbenchContext"
import { waiverDebtRows, waiverDebtSummaryRows } from "../route-utils"
import {
  useProjectGovernanceRollupsQuery,
  useProjectSummaryQuery,
  useFindingsQuery,
  useWaiversQuery,
} from "../useWorkbenchQueries"
import { invalidateProjectScopedWorkbenchQueries } from "../workbench-query-keys"

function WaiversRouteContent() {
  const queryClient = useQueryClient()
  const {
    projectListLoading,
    projects,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const queryProjectId = selectedProjectId
  const projectSummaryQuery = useProjectSummaryQuery(queryProjectId)
  const projectGovernanceRollupsQuery =
    useProjectGovernanceRollupsQuery(queryProjectId)
  const findingsQuery = useFindingsQuery(
    {
      limit: 500,
      offset: 0,
      project_id: queryProjectId,
      sort: "operational",
    },
    Boolean(queryProjectId),
  )
  const waiversQuery = useWaiversQuery(queryProjectId, Boolean(queryProjectId))
  const [waiverActionError, setWaiverActionError] = useState("")
  const [waiverActionMessage, setWaiverActionMessage] = useState("")
  const [waiverForm, setWaiverForm] =
    useState<WaiverFormState>(waiverFormDefaults)
  const [waiverEditForm, setWaiverEditForm] =
    useState<WaiverFormState>(waiverFormDefaults)
  const [waiverDrawerMode, setWaiverDrawerMode] =
    useState<WaiverDrawerMode>(null)
  const [selectedWaiverId, setSelectedWaiverId] = useState("")
  const waiverDrawerModeRef = useRef(waiverDrawerMode)
  const createWaiverMutation = useMutation({
    mutationFn: ({
      projectId,
      waiverCreate,
    }: {
      projectId: string
      waiverCreate: ReturnType<typeof waiverRequestBody>
    }) =>
      WaiversService.createProjectWaiver({
        project_id: projectId,
        waiverCreate,
      }),
  })
  const expireWaiverMutation = useMutation({
    mutationFn: (waiverId: string) =>
      WaiversService.expireWaiver({ waiver_id: waiverId }),
  })
  const updateWaiverMutation = useMutation({
    mutationFn: ({
      waiverId,
      waiverUpdate,
    }: {
      waiverId: string
      waiverUpdate: ReturnType<typeof waiverRequestBody>
    }) =>
      WaiversService.updateWaiver({
        waiver_id: waiverId,
        waiverUpdate,
      }),
  })

  const waivers = waiversQuery.data?.data ?? []
  const selectedWaiver = useMemo(
    () => waivers.find((waiver) => waiver.id === selectedWaiverId) ?? null,
    [selectedWaiverId, waivers],
  )

  useEffect(() => {
    waiverDrawerModeRef.current = waiverDrawerMode
  }, [waiverDrawerMode])

  function refreshWaivers() {
    if (!selectedProjectId) {
      return
    }
    void invalidateProjectScopedWorkbenchQueries(queryClient, selectedProjectId)
  }

  function updateWaiverFormField(field: keyof WaiverFormState, value: string) {
    setWaiverForm((form) => ({
      ...form,
      [field]: value,
    }))
  }

  function updateWaiverEditFormField(
    field: keyof WaiverFormState,
    value: string,
  ) {
    setWaiverEditForm((form) => ({
      ...form,
      [field]: value,
    }))
  }

  function openWaiverDrawer(
    mode: Exclude<WaiverDrawerMode, null>,
    waiver?: WaiverPublic,
  ) {
    setWaiverActionError("")
    setWaiverActionMessage("")
    if (waiver) {
      setSelectedWaiverId(waiver.id)
      setWaiverEditForm(waiverFormFromWaiver(waiver))
    }
    if (mode === "create") {
      setSelectedWaiverId("")
    }
    setWaiverDrawerMode(mode)
  }

  function closeWaiverDrawer() {
    setWaiverDrawerMode(null)
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
      setWaiverActionError("Select a project before recording accepted risk.")
      return
    }

    try {
      const waiver = await createWaiverMutation.mutateAsync({
        projectId: selectedProjectId,
        waiverCreate: waiverRequestBody(waiverForm),
      })
      setWaiverForm(waiverFormDefaults())
      setSelectedWaiverId(waiver.id)
      setWaiverDrawerMode(null)
      setWaiverActionMessage(
        `Accepted-risk decision created for ${waiverScopeLabel(waiver)}.`,
      )
      refreshWaivers()
    } catch (caught) {
      setWaiverActionError(apiErrorMessage("Acceptance create failed", caught))
    }
  }

  async function updateWaiver(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setWaiverActionError("")
    setWaiverActionMessage("")
    const validationError = validateWaiverForm(waiverEditForm)
    if (validationError) {
      setWaiverActionError(validationError)
      return
    }
    if (!selectedWaiverId) {
      setWaiverActionError("Select a risk acceptance before updating it.")
      return
    }
    try {
      const waiver = await updateWaiverMutation.mutateAsync({
        waiverId: selectedWaiverId,
        waiverUpdate: waiverRequestBody(waiverEditForm),
      })
      setSelectedWaiverId(waiver.id)
      setWaiverDrawerMode("detail")
      setWaiverActionMessage(
        `Accepted-risk decision updated for ${waiverScopeLabel(waiver)}.`,
      )
      refreshWaivers()
    } catch (caught) {
      setWaiverActionError(apiErrorMessage("Acceptance update failed", caught))
    }
  }

  async function expireWaiver(waiver: WaiverPublic) {
    setWaiverActionError("")
    setWaiverActionMessage("")
    try {
      const expired = await expireWaiverMutation.mutateAsync(waiver.id)
      setSelectedWaiverId(expired.id)
      if (waiverDrawerModeRef.current === "expire") {
        setWaiverDrawerMode("detail")
      }
      setWaiverActionMessage(
        `Accepted-risk decision for ${waiverScopeLabel(expired)} is now expired.`,
      )
      refreshWaivers()
    } catch (caught) {
      setWaiverActionError(apiErrorMessage("Acceptance expire failed", caught))
    }
  }

  const governanceRollups = projectGovernanceRollupsQuery.data ?? null
  const effectiveFindings = findingsQuery.data?.data ?? []
  const effectiveSummary = projectSummaryQuery.data ?? null

  return (
    <section className="w-full">
      <WaiversWorkbench
        findings={effectiveFindings}
        findingsError={
          findingsQuery.isError
            ? apiErrorMessage("Findings unavailable", findingsQuery.error)
            : ""
        }
        findingsLoading={findingsQuery.isLoading || findingsQuery.isFetching}
        onCreateWaiver={createWaiver}
        onExpireWaiver={(waiver) => void expireWaiver(waiver)}
        onFieldChange={updateWaiverFormField}
        onProjectChange={(projectId) => {
          setSelectedProjectId(projectId)
          setWaiverDrawerMode(null)
          setSelectedWaiverId("")
          setWaiverActionMessage("")
          setWaiverActionError("")
        }}
        onRefreshWaivers={refreshWaivers}
        onReviewFieldChange={updateWaiverEditFormField}
        onUpdateWaiver={updateWaiver}
        openWaiverDrawer={openWaiverDrawer}
        closeWaiverDrawer={closeWaiverDrawer}
        projectListLoading={projectListLoading}
        projectSummary={effectiveSummary}
        projects={projects}
        selectedWaiver={selectedWaiver}
        selectedWaiverId={selectedWaiverId}
        selectedProject={selectedProject}
        selectedProjectId={selectedProjectId}
        waiverActionError={waiverActionError}
        waiverActionLoading={
          createWaiverMutation.isPending ||
          expireWaiverMutation.isPending ||
          updateWaiverMutation.isPending
        }
        waiverActionMessage={waiverActionMessage}
        waiverDebtItems={waiverDebtRows(governanceRollups)}
        waiverDebtSummary={waiverDebtSummaryRows(governanceRollups)}
        waiverDrawerMode={waiverDrawerMode}
        waiverEditForm={waiverEditForm}
        waiverForm={waiverForm}
        waivers={waivers}
        waiversError={
          (waiversQuery.isError
            ? apiErrorMessage(
                "Accepted-risk decisions unavailable",
                waiversQuery.error,
              )
            : "") ||
          (projectGovernanceRollupsQuery.isError
            ? apiErrorMessage(
                "Governance rollups unavailable",
                projectGovernanceRollupsQuery.error,
              )
            : "")
        }
        waiversLoading={
          waiversQuery.isLoading ||
          waiversQuery.isFetching ||
          projectGovernanceRollupsQuery.isLoading ||
          projectGovernanceRollupsQuery.isFetching
        }
      />
    </section>
  )
}

export function WaiversRoute() {
  return <WaiversRouteContent />
}
