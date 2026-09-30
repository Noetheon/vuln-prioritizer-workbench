import {
  defaultFindingsSearchState,
  type FindingsSearchState,
} from "./findings-search-types.ts"
import type { FindingsSavedView } from "./remediation-queue-model.ts"

// Statuses outside open work belong to the Accepted and Fixed views, or to
// "all statuses"; another view returns to open work.
const nonOpenWorkStatuses = new Set<string>([
  "accepted",
  "all",
  "false_positive",
  "fixed",
  "resolved",
  "suppressed",
])

/**
 * The queue after choosing a view. A view sets its own condition and
 * replaces another view's (SLA, KEV, exposure, or a closed status); the
 * search, owner, priority, open-work status, and score filters stay.
 */
export function findingsSearchForSavedView(
  search: FindingsSearchState,
  view: FindingsSavedView,
): FindingsSearchState {
  const base: FindingsSearchState = {
    ...search,
    direction: defaultFindingsSearchState.direction,
    exposure: "",
    kev: "",
    offset: 0,
    sla: "",
    sort: defaultFindingsSearchState.sort,
    status: nonOpenWorkStatuses.has(search.status) ? "" : search.status,
  }

  switch (view) {
    case "accepted":
      return { ...base, direction: "desc", sort: "last_seen", status: "accepted" }
    case "fixed":
      return { ...base, direction: "desc", sort: "last_seen", status: "fixed" }
    case "immediate":
      return {
        ...base,
        direction: "asc",
        priority: "critical",
        sort: "priority",
        status: "open",
      }
    case "overdue":
      return { ...base, direction: "asc", sla: "overdue", sort: "priority" }
    case "internet":
      return {
        ...base,
        direction: "asc",
        exposure: "internet-facing",
        sort: "priority",
      }
    case "kev":
      return { ...base, direction: "desc", kev: "true", sort: "kev" }
    case "all":
      return { ...base, status: "" }
    case "custom":
      return base
  }
}
