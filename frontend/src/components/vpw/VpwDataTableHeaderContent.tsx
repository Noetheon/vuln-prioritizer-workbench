import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"
import type { ReactNode } from "react"
import { Button } from "@/components/ui/button"
import type { VpwDataTableColumn, VpwDataTableSort } from "./VpwDataTable"

export function VpwDataTableHeaderContent<TData>({
  column,
}: {
  column: VpwDataTableColumn<TData>
}) {
  if (!column.sort) return <>{column.header}</>
  return <VpwTableSortButton sort={column.sort}>{column.header}</VpwTableSortButton>
}

/** One sort control; a header that combines two columns shows two. */
export function VpwTableSortButton({
  children,
  sort,
}: {
  children: ReactNode
  sort: VpwDataTableSort
}) {
  const Icon = sort.active
    ? sort.direction === "asc"
      ? ArrowUp
      : ArrowDown
    : ArrowUpDown

  return (
    <Button
      aria-label={`Sort by ${sort.label}`}
      aria-pressed={sort.active}
      className="vpw-table-sort-button"
      onClick={sort.onSort}
      size="xs"
      type="button"
      variant="ghost"
    >
      <Icon aria-hidden="true" className="vpw-table-sort-button__icon" />
      <span>{children}</span>
    </Button>
  )
}
