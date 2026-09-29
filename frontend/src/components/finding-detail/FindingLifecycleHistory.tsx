import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { FindingsService } from "@/api-client"
import { formatDateTime } from "@/components/dashboard/dashboard-model"
import { Button } from "@/components/ui/button"
import { StatusLozenge } from "@/components/vpw"
import { apiErrorMessage } from "@/lib/app-errors"
import { lifecycleSourceLabel } from "@/lib/finding-status-transitions"
import { Link } from "@/lib/router"
import { workbenchQueryKeys } from "@/workbench/workbench-query-keys"

const pageSize = 10

export function FindingLifecycleHistory({
  findingId,
  projectId,
}: {
  findingId: string
  projectId: string
}) {
  const [offset, setOffset] = useState(0)
  const events = useQuery({
    queryKey: workbenchQueryKeys.findingLifecycleEvents(findingId, offset),
    queryFn: ({ signal }) =>
      FindingsService.readFindingLifecycleEvents(
        { finding_id: findingId, offset, limit: pageSize },
        { signal },
      ),
    retry: false,
  })
  const rows = events.data?.data ?? []
  const count = events.data?.count ?? 0
  return (
    <section
      aria-label="Status changes"
      className="grid min-w-0 grid-cols-1 gap-4"
    >
      <div>
        <h3 className="font-semibold">Status changes</h3>
        <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
          Who or what changed the workflow status, and why. Rescans resolve
          findings they no longer report and reopen resolved findings they
          report again.
        </p>
      </div>
      {events.isPending ? <p role="status">Loading status changes…</p> : null}
      {events.isError ? (
        <div role="alert">
          <p>{apiErrorMessage("Status history unavailable", events.error)}</p>
          <Button variant="outline" onClick={() => void events.refetch()}>
            Retry
          </Button>
        </div>
      ) : null}
      {!events.isPending && !events.isError && rows.length === 0 ? (
        <p>No status changes are recorded for this finding yet.</p>
      ) : null}
      {rows.length ? (
        <ol className="grid gap-3">
          {rows.map((event) => (
            <li
              key={event.id}
              className="min-w-0 rounded-lg border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2 text-sm font-semibold">
                  <StatusLozenge density="compact" status={event.from_status} />
                  <span aria-hidden="true">→</span>
                  <span className="sr-only">changed to</span>
                  <StatusLozenge density="compact" status={event.to_status} />
                </div>
                <span className="text-xs">
                  {formatDateTime(event.created_at)}
                </span>
              </div>
              <p className="mt-2 text-sm">
                {lifecycleSourceLabel(event.source)}
                {event.actor ? ` · ${event.actor}` : ""}
              </p>
              <p className="mt-2 text-sm break-words text-[var(--vpw-text-secondary)]">
                {event.reason ?? "No reason recorded."}
              </p>
              {event.analysis_run_id ? (
                <p className="mt-2 text-xs">
                  <Link
                    params={{ runId: event.analysis_run_id }}
                    search={{ projectId }}
                    to="/imports/runs/$runId"
                  >
                    {`Open import run ${event.analysis_run_id.slice(0, 8)}`}
                  </Link>
                </p>
              ) : null}
            </li>
          ))}
        </ol>
      ) : null}
      {count > pageSize ? (
        <nav
          aria-label="Status change pages"
          className="flex items-center justify-between gap-2"
        >
          <Button
            disabled={offset === 0 || events.isFetching}
            variant="outline"
            onClick={() => setOffset(Math.max(0, offset - pageSize))}
          >
            Newer changes
          </Button>
          <span className="text-xs">
            {offset + 1}–{Math.min(offset + pageSize, count)} of {count}
          </span>
          <Button
            disabled={offset + pageSize >= count || events.isFetching}
            variant="outline"
            onClick={() => setOffset(offset + pageSize)}
          >
            Older changes
          </Button>
        </nav>
      ) : null}
    </section>
  )
}
