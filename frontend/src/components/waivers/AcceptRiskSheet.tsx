import { useMutation, useQueryClient } from "@tanstack/react-query"
import { type FormEvent, useState } from "react"
import { WaiversService } from "@/api-client"
import { DetailDrawer, VpwStatusBanner } from "@/components/vpw"
import { apiErrorMessage } from "@/lib/app-errors"
import {
  findingWaiverForm,
  validateWaiverForm,
  waiverBulkRequestBody,
  type WaiverFormState,
  waiverFormDefaults,
  waiverRequestBody,
} from "@/lib/waiver-view"
import { invalidateProjectScopedWorkbenchQueries } from "@/workbench/workbench-query-keys"
import type { AcceptableFinding } from "./waiver-scope-model"
import { WaiverForm } from "./WaiversWorkbenchForm"

export function acceptedRiskMessage(count: number) {
  return `Accepted risk recorded for ${count} finding${count === 1 ? "" : "s"}.`
}

/**
 * Accepts the risk of chosen findings where they are, from Triage or a
 * finding: one time-bound acceptance per finding with a shared decision.
 */
export function AcceptRiskSheet({
  findings,
  onAccepted,
  onOpenChange,
  open,
  projectId,
}: {
  findings: readonly AcceptableFinding[]
  onAccepted: (message: string) => void
  onOpenChange: (open: boolean) => void
  open: boolean
  projectId: string
}) {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<WaiverFormState>(waiverFormDefaults)
  const [error, setError] = useState("")
  const acceptMutation = useMutation({
    mutationFn: async (decision: WaiverFormState) => {
      const [only] = findings
      if (findings.length === 1 && only) {
        await WaiversService.createProjectWaiver({
          project_id: projectId,
          waiverCreate: waiverRequestBody(findingWaiverForm(decision, only)),
        })
        return 1
      }
      const created = await WaiversService.createProjectWaiversBulk({
        project_id: projectId,
        waiverBulkCreate: waiverBulkRequestBody(
          decision,
          findings.map((finding) => finding.id),
        ),
      })
      return created.count
    },
  })

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const [first] = findings
    // The chosen findings are the scope; the rest is checked like any form.
    const validation = first
      ? validateWaiverForm(findingWaiverForm(form, first))
      : "Choose at least one finding."
    if (validation) {
      setError(validation)
      return
    }
    setError("")
    try {
      const count = await acceptMutation.mutateAsync(form)
      await invalidateProjectScopedWorkbenchQueries(queryClient, projectId)
      setForm(waiverFormDefaults())
      onAccepted(acceptedRiskMessage(count))
      onOpenChange(false)
    } catch (caught) {
      setError(apiErrorMessage("Risk acceptance failed", caught))
    }
  }

  return (
    <DetailDrawer
      className="w-[min(100vw,52rem)] sm:max-w-none"
      description="Record a time-bound accepted-risk decision with an owner, a reason, and approval evidence."
      onOpenChange={(nextOpen) => {
        if (!nextOpen) setError("")
        onOpenChange(nextOpen)
      }}
      open={open}
      title="Accept risk"
    >
      <div className="flex flex-col gap-4">
        {error ? (
          <VpwStatusBanner title="Risk acceptance failed" tone="critical">
            {error}
          </VpwStatusBanner>
        ) : null}
        <WaiverForm
          buttonLabel={
            findings.length === 1
              ? "Accept risk"
              : `Accept risk for ${findings.length} findings`
          }
          findings={[]}
          findingsLoading={false}
          fixedFindings={findings}
          onCancel={() => onOpenChange(false)}
          onFieldChange={(field, value) =>
            setForm((current) => ({ ...current, [field]: value }))
          }
          onSubmit={(event) => void submit(event)}
          waiverActionLoading={acceptMutation.isPending}
          waiverForm={form}
        />
      </div>
    </DetailDrawer>
  )
}
