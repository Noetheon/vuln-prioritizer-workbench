import { useState } from "react"
import type { FindingDetailPublic, FindingStatus } from "@/api-client"
import { FindingsService } from "@/api-client"
import { FindingStatusReasonDialog } from "@/components/findings/FindingStatusReasonDialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { apiErrorMessage } from "@/lib/app-errors"
import {
  isManualStatus,
  manualStatusOptions,
  statusRequiresReason,
  statusUpdateRequest,
} from "@/lib/finding-status-transitions"

export function FindingWorkflowStatusControl({
  finding,
  onRefresh,
}: {
  finding: FindingDetailPublic
  onRefresh: () => void
}) {
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState("")
  const [pendingStatus, setPendingStatus] = useState<FindingStatus | null>(null)

  async function applyStatus(status: FindingStatus, reason = "") {
    setSaving(true)
    setSaveError("")
    try {
      await FindingsService.updateFindingStatus({
        finding_id: finding.id,
        findingStatusUpdateRequest: statusUpdateRequest(status, reason),
      })
      setPendingStatus(null)
      onRefresh()
    } catch (error) {
      setSaveError(apiErrorMessage("Status update failed", error))
    } finally {
      setSaving(false)
    }
  }

  function chooseStatus(status: FindingStatus) {
    if (status === finding.status) return
    if (statusRequiresReason(status)) {
      setSaveError("")
      setPendingStatus(status)
      return
    }
    void applyStatus(status)
  }

  return (
    <div className="finding-detail-action-block">
      <span>Workflow status</span>
      {isManualStatus(finding.status) ? (
        <>
          <Select
            disabled={saving}
            onValueChange={(value) => chooseStatus(value as FindingStatus)}
            value={finding.status}
          >
            <SelectTrigger
              aria-label="Workflow status"
              className="w-full bg-[var(--vpw-bg-card)]"
            >
              <SelectValue placeholder="Set status" />
            </SelectTrigger>
            <SelectContent>
              {manualStatusOptions.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {saveError && pendingStatus === null ? (
            <p className="finding-detail-action-error" role="alert">
              {saveError}
            </p>
          ) : null}
          <FindingStatusReasonDialog
            count={1}
            error={pendingStatus !== null ? saveError : ""}
            onCancel={() => {
              setPendingStatus(null)
              setSaveError("")
            }}
            onConfirm={(reason) => {
              if (pendingStatus) void applyStatus(pendingStatus, reason)
            }}
            pending={saving}
            status={pendingStatus}
          />
        </>
      ) : (
        <p>
          Managed by governance evidence (waiver or VEX) - use Risk acceptance
          or evidence updates to change it.
        </p>
      )}
    </div>
  )
}
