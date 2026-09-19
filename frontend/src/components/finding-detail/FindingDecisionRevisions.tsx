import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { EvaluationsService } from "@/api-client"
import { formatDateTime } from "@/components/dashboard/dashboard-model"
import { Button } from "@/components/ui/button"
import { apiErrorMessage } from "@/lib/app-errors"
import { workbenchQueryKeys } from "@/workbench/workbench-query-keys"
import { revisionDifferenceRows } from "./finding-revisions-model"

const pageSize = 10

export function FindingDecisionRevisions({ findingId }: { findingId: string }) {
  const [offset, setOffset] = useState(0)
  const revisions = useQuery({
    queryKey: workbenchQueryKeys.findingRevisions(findingId, offset),
    queryFn: ({ signal }) =>
      EvaluationsService.listDecisionRevisions(
        { finding_id: findingId, offset, limit: pageSize + 1 },
        { signal },
      ),
    retry: false,
  })
  const rows = revisions.data?.data ?? []
  return (
    <section
      aria-label="Decision revisions"
      className="grid min-w-0 grid-cols-1 gap-4"
    >
      <div>
        <h3 className="font-semibold">Decision revisions</h3>
        <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
          Evaluation time records when a decision was calculated. Observation
          time records when its scanner evidence was last seen.
        </p>
      </div>
      {revisions.isPending ? (
        <p role="status">Loading decision revisions…</p>
      ) : null}
      {revisions.isError ? (
        <div role="alert">
          <p>
            {apiErrorMessage("Decision history unavailable", revisions.error)}
          </p>
          <Button variant="outline" onClick={() => void revisions.refetch()}>
            Retry
          </Button>
        </div>
      ) : null}
      {!revisions.isPending && !revisions.isError && rows.length === 0 ? (
        <p>No decision revisions are recorded for this finding.</p>
      ) : null}
      {rows.slice(0, pageSize).map((revision, index) => {
        const previous = rows[index + 1]
        const differences = revisionDifferenceRows(revision, previous)
        return (
          <article
            key={revision.id}
            className="min-w-0 rounded-lg border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h4 className="text-sm font-semibold">
                {revision.cause.replaceAll("_", " ")}
                {revision.is_current ? " · Current" : ""}
              </h4>
              <span className="text-xs">
                Evaluated {formatDateTime(revision.evaluated_at)}
              </span>
            </div>
            <p className="mt-2 text-sm">
              {revision.priority} · {revision.status} · Risk score{" "}
              {revision.risk_score ?? "not scored"} · Rank{" "}
              {revision.operational_rank ?? "not recorded"}
            </p>
            <p className="mt-2 text-sm text-[var(--vpw-text-secondary)]">
              {revision.rationale ?? "No rationale recorded."}
            </p>
            <p className="mt-2 text-sm">
              {revision.recommended_action ?? "No recommended action recorded."}
            </p>
            <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
              <div>
                <dt className="text-[var(--vpw-text-muted)]">Last observed</dt>
                <dd>
                  {revision.observed_at
                    ? formatDateTime(revision.observed_at)
                    : "Not recorded"}
                </dd>
              </div>
              <div>
                <dt className="text-[var(--vpw-text-muted)]">Replay inputs</dt>
                <dd>
                  {revision.replay_status === "available"
                    ? "Recorded"
                    : "Unavailable for this legacy revision"}
                </dd>
              </div>
              <div>
                <dt className="text-[var(--vpw-text-muted)]">
                  Provider snapshot
                </dt>
                <dd className="break-all">
                  {revision.provider_snapshot_id ?? "Not recorded"}
                </dd>
              </div>
              <div>
                <dt className="text-[var(--vpw-text-muted)]">Engine version</dt>
                <dd>{revision.engine_version ?? "Not recorded"}</dd>
              </div>
              <div>
                <dt className="text-[var(--vpw-text-muted)]">Evaluation run</dt>
                <dd className="break-all">{revision.analysis_run_id}</dd>
              </div>
              {revision.input_sha256 ? (
                <div>
                  <dt className="text-[var(--vpw-text-muted)]">
                    Input fingerprint
                  </dt>
                  <dd className="break-all">{revision.input_sha256}</dd>
                </div>
              ) : null}
            </dl>
            {revision.changed_fields?.length ? (
              <p className="mt-3 text-xs text-[var(--vpw-text-secondary)]">
                Changed evidence fields:{" "}
                {revision.changed_fields
                  .map((field) => field.replaceAll("_", " "))
                  .join(", ")}
              </p>
            ) : null}
            {previous ? (
              <details className="mt-3 text-sm">
                <summary className="cursor-pointer font-medium">
                  Changes from previous revision ({differences.length})
                </summary>
                {differences.length ? (
                  <dl className="mt-2 grid gap-2">
                    {differences.map((difference) => (
                      <div key={difference.field}>
                        <dt className="text-[var(--vpw-text-muted)]">
                          {difference.label}
                        </dt>
                        <dd className="break-words">
                          {difference.before} → {difference.after}
                        </dd>
                      </div>
                    ))}
                  </dl>
                ) : (
                  <p className="mt-2">
                    The displayed decision fields are unchanged. See the
                    recorded changed fields above for other evidence updates.
                  </p>
                )}
              </details>
            ) : (
              <p className="mt-3 text-xs text-[var(--vpw-text-muted)]">
                First recorded decision; no previous revision to compare.
              </p>
            )}
          </article>
        )
      })}
      {revisions.data && revisions.data.count > pageSize ? (
        <nav
          aria-label="Decision revision pages"
          className="flex items-center justify-between gap-2"
        >
          <Button
            disabled={offset === 0 || revisions.isFetching}
            variant="outline"
            onClick={() => setOffset(Math.max(0, offset - pageSize))}
          >
            Newer revisions
          </Button>
          <span className="text-xs">
            {offset + 1}–{Math.min(offset + pageSize, revisions.data.count)} of{" "}
            {revisions.data.count}
          </span>
          <Button
            disabled={
              offset + pageSize >= revisions.data.count || revisions.isFetching
            }
            variant="outline"
            onClick={() => setOffset(offset + pageSize)}
          >
            Older revisions
          </Button>
        </nav>
      ) : null}
    </section>
  )
}
