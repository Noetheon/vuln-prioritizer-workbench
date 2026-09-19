import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { RefreshCcw } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { EvaluationsService } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { apiErrorMessage } from "@/lib/app-errors"
import {
  invalidateProjectScopedWorkbenchQueries,
  workbenchQueryKeys,
} from "@/workbench/workbench-query-keys"

const pendingStatuses = new Set(["pending", "queued", "running"])

export function ReevaluateControl({
  projectId,
  findingIds,
  latestProviderSnapshotId,
}: {
  projectId: string
  findingIds?: string[]
  latestProviderSnapshotId?: string | null
}) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [providerMode, setProviderMode] = useState("recorded")
  const [reason, setReason] = useState("")
  const refreshedRun = useRef("")
  const evaluations = useQuery({
    queryKey: workbenchQueryKeys.projectEvaluations(projectId),
    enabled: Boolean(projectId),
    queryFn: ({ signal }) =>
      EvaluationsService.listEvaluations(
        { project_id: projectId, limit: 5, offset: 0 },
        { signal },
      ),
    refetchInterval: (query) =>
      query.state.data?.data.some((run) => pendingStatuses.has(run.status))
        ? 2000
        : false,
    retry: false,
  })
  const mutation = useMutation({
    mutationFn: () =>
      EvaluationsService.createEvaluation({
        project_id: projectId,
        body: {
          finding_ids: findingIds,
          provider_snapshot_id:
            providerMode === "latest" ? latestProviderSnapshotId : undefined,
          reason: reason.trim() || undefined,
        },
      }),
    onSuccess: async () => {
      setOpen(false)
      await queryClient.invalidateQueries({
        queryKey: workbenchQueryKeys.projectEvaluations(projectId),
      })
    },
  })
  const latest = evaluations.data?.data[0]
  const latestId = latest?.id
  const latestStatus = latest?.status
  const busy =
    mutation.isPending ||
    Boolean(
      evaluations.data?.data.some((run) => pendingStatuses.has(run.status)),
    )

  useEffect(() => {
    if (!latestId || !latestStatus || pendingStatuses.has(latestStatus)) return
    const key = `${latestId}:${latestStatus}`
    if (refreshedRun.current === key) return
    refreshedRun.current = key
    void invalidateProjectScopedWorkbenchQueries(queryClient, projectId)
    void queryClient.invalidateQueries({
      queryKey: [...workbenchQueryKeys.all, "finding-detail"],
    })
    void queryClient.invalidateQueries({
      queryKey: [...workbenchQueryKeys.all, "finding-revisions"],
    })
  }, [latestId, latestStatus, projectId, queryClient])

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogTrigger asChild>
          <Button disabled={!projectId || busy} size="sm" variant="outline">
            <RefreshCcw size={14} aria-hidden="true" />
            {busy ? "Re-evaluating…" : "Re-evaluate"}
          </Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Re-evaluate {findingIds ? "this finding" : "project findings"}
            </DialogTitle>
            <DialogDescription>
              Create a new decision revision from stored observations and
              current asset and governance context. This does not perform a new
              scan or prove that a vulnerability was fixed.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="evaluation-provider">Provider evidence</Label>
            <Select value={providerMode} onValueChange={setProviderMode}>
              <SelectTrigger id="evaluation-provider">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="recorded">
                  Keep recorded provider evidence
                </SelectItem>
                <SelectItem value="latest" disabled={!latestProviderSnapshotId}>
                  Use latest provider snapshot
                </SelectItem>
              </SelectContent>
            </Select>
            {providerMode === "latest" && latestProviderSnapshotId ? (
              <p className="break-all text-xs text-[var(--vpw-text-muted)]">
                Snapshot: {latestProviderSnapshotId}
              </p>
            ) : null}
            <Label htmlFor="evaluation-reason">Reason (optional)</Label>
            <Input
              id="evaluation-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              maxLength={1000}
              placeholder="For example: provider evidence refreshed"
            />
            {mutation.isError ? (
              <p
                role="alert"
                className="text-sm text-[var(--vpw-color-critical)]"
              >
                {apiErrorMessage("Re-evaluation failed", mutation.error)}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button onClick={() => mutation.mutate()} disabled={busy}>
              Start re-evaluation
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {latest ? (
        <span
          role="status"
          className="text-xs text-[var(--vpw-text-secondary)]"
        >
          Latest project evaluation: {latest.status}
          {latest.error_message ? ` · ${latest.error_message}` : ""}
        </span>
      ) : null}
      {evaluations.isError ? (
        <span role="alert" className="text-xs">
          {apiErrorMessage("Evaluation history unavailable", evaluations.error)}
        </span>
      ) : null}
    </div>
  )
}
