import { useMutation, useQueryClient } from "@tanstack/react-query"
import { type FormEvent, useState } from "react"
import { WaiversService, type WaiverPublic } from "../../api-client"
import { WaiversWorkbench } from "../../components/waivers/WaiversWorkbench"
import { apiErrorMessage } from "../../lib/app-errors"
import {
  validateWaiverForm,
  type WaiverFormState,
  waiverFormDefaults,
  waiverRequestBody,
  waiverScopeLabel,
} from "../../lib/waiver-view"
import { WorkbenchShell } from "../WorkbenchShell"
import { useWorkbenchContext } from "../WorkbenchContext"
import {
  waiverDebtRows,
  waiverDebtSummaryRows,
} from "../route-utils"
import {
  useProjectGovernanceRollupsQuery,
  useProjectSummaryQuery,
  useWaiversQuery,
} from "../useWorkbenchQueries"
import { workbenchQueryKeys } from "../workbench-query-keys"

function WaiversRouteContent() {
  const queryClient = useQueryClient()
  const {
    projectListLoading,
    projects,
    selectedProject,
    selectedProjectId,
    setSelectedProjectId,
  } = useWorkbenchContext()
  const projectSummaryQuery = useProjectSummaryQuery(selectedProjectId)
  const projectGovernanceRollupsQuery =
    useProjectGovernanceRollupsQuery(selectedProjectId)
  const waiversQuery = useWaiversQuery(selectedProjectId, true)
  const [waiverActionError, setWaiverActionError] = useState("")
  const [waiverActionMessage, setWaiverActionMessage] = useState("")
  const [waiverForm, setWaiverForm] =
    useState<WaiverFormState>(waiverFormDefaults)
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

  function refreshWaivers() {
    if (!selectedProjectId) {
      return
    }
    void queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.waivers(selectedProjectId),
    })
    void queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectGovernanceRollups(selectedProjectId),
    })
    void queryClient.invalidateQueries({
      queryKey: workbenchQueryKeys.projectSummary(selectedProjectId),
    })
  }

  function refreshFindings() {
    void queryClient.invalidateQueries({
      queryKey: ["workbench", "findings"],
    })
    if (selectedProjectId) {
      void queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.dashboardFindings(selectedProjectId),
      })
      void queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.dashboardSignalCounts(selectedProjectId),
      })
    }
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

    try {
      const waiver = await createWaiverMutation.mutateAsync({
        projectId: selectedProjectId,
        waiverCreate: waiverRequestBody(waiverForm),
      })
      setWaiverForm(waiverFormDefaults())
      setWaiverActionMessage(
        `Accepted risk waiver created for ${waiverScopeLabel(waiver)}.`,
      )
      refreshWaivers()
      refreshFindings()
    } catch (caught) {
      setWaiverActionError(apiErrorMessage("Waiver create failed", caught))
    }
  }

  async function expireWaiver(waiver: WaiverPublic) {
    setWaiverActionError("")
    setWaiverActionMessage("")
    try {
      const expired = await expireWaiverMutation.mutateAsync(waiver.id)
      setWaiverActionMessage(
        `Waiver for ${waiverScopeLabel(expired)} is now expired.`,
      )
      refreshWaivers()
      refreshFindings()
    } catch (caught) {
      setWaiverActionError(apiErrorMessage("Waiver expire failed", caught))
    }
  }

  const governanceRollups = projectGovernanceRollupsQuery.data ?? null

  return (
    <section className="mx-auto w-full max-w-screen-2xl px-4 py-6 sm:px-6">
      <WaiversWorkbench
        onCreateWaiver={createWaiver}
        onExpireWaiver={(waiver) => void expireWaiver(waiver)}
        onFieldChange={updateWaiverFormField}
        onProjectChange={setSelectedProjectId}
        onRefreshWaivers={refreshWaivers}
        projectListLoading={projectListLoading}
        projectSummary={projectSummaryQuery.data ?? null}
        projects={projects}
        selectedProject={selectedProject}
        selectedProjectId={selectedProjectId}
        waiverActionError={waiverActionError}
        waiverActionLoading={
          createWaiverMutation.isPending || expireWaiverMutation.isPending
        }
        waiverActionMessage={waiverActionMessage}
        waiverDebtItems={waiverDebtRows(governanceRollups)}
        waiverDebtSummary={waiverDebtSummaryRows(governanceRollups)}
        waiverForm={waiverForm}
        waivers={waiversQuery.data?.data ?? []}
        waiversError={
          (waiversQuery.isError
            ? apiErrorMessage("Waivers unavailable", waiversQuery.error)
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
  return (
    <WorkbenchShell routePath="/waivers">
      <WaiversRouteContent />
    </WorkbenchShell>
  )
}
