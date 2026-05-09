import type { FindingPublic } from "@/api-client"
import { cn } from "@/lib/utils"
import { buildFindingsDataTableColumns } from "./FindingsDataTableColumns"
import type { FindingsUrlSearch } from "./findings-search-state"
import type { FindingsDirection, QueueSort } from "./remediation-queue-model"

export type { QueueSort } from "./remediation-queue-model"

type FindingsDataTableProps = {
  findings: readonly FindingPublic[]
  findingDirection: FindingsDirection
  findingSearch: FindingsUrlSearch
  onOpenSheet: (finding: FindingPublic) => void
  onOpenWhy: (finding: FindingPublic) => void
  onSort: (sort: QueueSort) => void
  queueSort: QueueSort
}

export function FindingsDataTable({
  findings,
  findingDirection,
  findingSearch,
  onOpenSheet,
  onOpenWhy,
  onSort,
  queueSort,
}: FindingsDataTableProps) {
  const columns = buildFindingsDataTableColumns({
    findingDirection,
    findingSearch,
    onOpenSheet,
    onOpenWhy,
    onSort,
    queueSort,
  })

  return (
    <section
      aria-label="Findings table scroll region"
      className="vpw-table-wrap remediation-table-wrap shadow-none"
      // biome-ignore lint/a11y/noNoninteractiveTabindex: The table overflow container must be keyboard-focusable for horizontal scroll access.
      tabIndex={0}
    >
      <table className="vpw-table table-fixed [&_td]:py-3 [&_th]:py-3">
        <caption className="sr-only">Findings remediation queue</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                aria-sort={column.ariaSort}
                className={cn("vpw-table-header-cell", column.headerClassName)}
                key={column.id}
                scope="col"
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr
              className="vpw-table-row transition-colors hover:[&>td]:bg-[var(--vpw-bg-panel)]"
              key={finding.id}
            >
              {columns.map((column) => (
                <td
                  className={cn("vpw-table-cell", column.className)}
                  key={column.id}
                >
                  {column.cell(finding)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
