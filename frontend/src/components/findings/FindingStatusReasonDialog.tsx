import { useEffect, useId, useState } from "react"
import type { FindingStatus } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import {
  FINDING_STATUS_REASON_MAX_LENGTH,
  manualStatusLabel,
  statusReasonError,
  statusRequiresReason,
} from "@/lib/finding-status-transitions"

export function FindingStatusReasonDialog({
  count,
  error,
  onCancel,
  onConfirm,
  pending,
  status,
}: {
  count: number
  error: string
  onCancel: () => void
  onConfirm: (reason: string) => void
  pending: boolean
  status: FindingStatus | null
}) {
  const reasonId = useId()
  const [reason, setReason] = useState("")
  const [touched, setTouched] = useState(false)

  useEffect(() => {
    if (status) {
      setReason("")
      setTouched(false)
    }
  }, [status])

  const label = status ? manualStatusLabel(status) : ""
  const validation = status ? statusReasonError(status, reason) : ""
  const required = status ? statusRequiresReason(status) : false
  const subject = count === 1 ? "this finding" : `${count} findings`

  return (
    <Dialog
      open={status !== null}
      onOpenChange={(open) => {
        if (!open && !pending) onCancel()
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{`Mark ${subject} as ${label.toLowerCase()}`}</DialogTitle>
          <DialogDescription>
            {status === "resolved"
              ? "Resolved findings leave the open queue. A later scan that reports the same finding again reopens it."
              : status === "false_positive"
                ? "False positives leave the open queue and stay closed when a scan reports them again."
                : "The status change and its reason are kept in the finding history."}
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            setTouched(true)
            if (!validation) onConfirm(reason)
          }}
        >
          <div className="grid gap-2">
            <Label htmlFor={reasonId}>
              {required ? "Reason (required)" : "Reason (optional)"}
            </Label>
            <Textarea
              aria-invalid={touched && Boolean(validation)}
              disabled={pending}
              id={reasonId}
              maxLength={FINDING_STATUS_REASON_MAX_LENGTH}
              onBlur={() => setTouched(true)}
              onChange={(event) => setReason(event.target.value)}
              placeholder={
                status === "false_positive"
                  ? "For example: the vulnerable module is not loaded in this service"
                  : "For example: upgraded to the fixed version in release 2026.10"
              }
              rows={4}
              value={reason}
            />
            {touched && validation ? (
              <p className="text-sm text-[var(--vpw-red)]" role="alert">
                {validation}
              </p>
            ) : null}
          </div>
          {error ? (
            <p className="text-sm text-[var(--vpw-red)]" role="alert">
              {error}
            </p>
          ) : null}
          <DialogFooter>
            <Button
              disabled={pending}
              onClick={onCancel}
              type="button"
              variant="outline"
            >
              Cancel
            </Button>
            <Button disabled={pending} type="submit">
              {pending ? "Saving…" : `Mark as ${label.toLowerCase()}`}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
