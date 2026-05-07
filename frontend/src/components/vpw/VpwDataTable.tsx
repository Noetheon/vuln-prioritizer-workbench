import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwDataTableColumn<TData> = {
  id: string
  header: ReactNode
  cell: (row: TData) => ReactNode
  className?: string
  headerClassName?: string
}

export type VpwDataTableDensity = "compact" | "standard" | "comfortable"

export type VpwDataTableProps<TData> = {
  columns: readonly VpwDataTableColumn<TData>[]
  data: readonly TData[]
  getRowKey: (row: TData, index: number) => string
  caption?: string
  className?: string
  density?: VpwDataTableDensity
  emptyState?: ReactNode
}

const densityClass: Record<VpwDataTableDensity, string> = {
  compact: "[&_td]:py-2 [&_th]:py-2",
  standard: "[&_td]:py-3 [&_th]:py-3",
  comfortable: "[&_td]:py-3.5 [&_th]:py-3",
}

export function VpwDataTable<TData>({
  caption,
  className,
  columns,
  data,
  density = "standard",
  emptyState,
  getRowKey,
}: VpwDataTableProps<TData>) {
  if (data.length === 0 && emptyState) {
    return <>{emptyState}</>
  }

  return (
    <section
      aria-label={caption ?? "Data table"}
      className={cn("vpw-table-wrap", className)}
      // biome-ignore lint/a11y/noNoninteractiveTabindex: Data table wrappers can scroll horizontally and need keyboard access.
      tabIndex={0}
    >
      <table className={cn("vpw-table", densityClass[density])}>
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead>
          <tr>
            {columns.map((column) => (
              <th
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
          {data.length > 0 ? (
            data.map((row, index) => (
              <tr className="vpw-table-row" key={getRowKey(row, index)}>
                {columns.map((column) => (
                  <td
                    className={cn("vpw-table-cell", column.className)}
                    key={column.id}
                  >
                    {column.cell(row)}
                  </td>
                ))}
              </tr>
            ))
          ) : (
            <tr className="vpw-table-row">
              <td className="vpw-table-cell" colSpan={columns.length}>
                <div className="py-8 text-center text-sm text-[var(--vpw-text-muted)]">
                  No records available.
                </div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  )
}
