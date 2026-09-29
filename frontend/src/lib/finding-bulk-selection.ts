import type { FindingBulkStatusUpdatePublic } from "../api-client"
import { manualStatusLabel } from "./finding-status-transitions.ts"

// Mirrors the API limit on one bulk status request.
export const BULK_STATUS_MAX_FINDINGS = 500

export type SelectAllState = boolean | "indeterminate"

// Keeps only selected findings that are still on screen, in screen order, so
// paging or filtering never applies a change to rows the analyst cannot see.
export function visibleSelection(
  selectedIds: ReadonlySet<string>,
  visibleIds: readonly string[],
) {
  return visibleIds.filter((id) => selectedIds.has(id))
}

export function toggleSelection(
  selectedIds: ReadonlySet<string>,
  id: string,
  checked: boolean,
) {
  const next = new Set(selectedIds)
  if (checked) next.add(id)
  else next.delete(id)
  return next
}

export function toggleAllSelection(
  visibleIds: readonly string[],
  checked: boolean,
) {
  return new Set(checked ? visibleIds : [])
}

export function selectAllState(
  selectedCount: number,
  visibleCount: number,
): SelectAllState {
  if (selectedCount === 0 || visibleCount === 0) return false
  if (selectedCount >= visibleCount) return true
  return "indeterminate"
}

export function selectedCountLabel(count: number) {
  return `${count} finding${count === 1 ? "" : "s"} selected`
}

export function bulkStatusOutcomeMessage(
  result: FindingBulkStatusUpdatePublic,
) {
  const updated = result.updated_count ?? result.updated_ids?.length ?? 0
  const skipped = result.skipped ?? []
  const label = manualStatusLabel(result.status).toLowerCase()
  const parts = [
    updated === 0
      ? "No findings changed."
      : `Marked ${updated} finding${updated === 1 ? "" : "s"} as ${label}.`,
  ]
  if (skipped.length) {
    const reasons = [...new Set(skipped.map((skip) => skip.detail))]
    parts.push(
      `${skipped.length} skipped: ${reasons.slice(0, 2).join(" ")}${
        reasons.length > 2 ? ` (+${reasons.length - 2} more reasons)` : ""
      }`,
    )
  }
  return parts.join(" ")
}
