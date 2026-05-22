import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import type { VpwDataTableColumn } from "./VpwDataTable"

export function VpwDataTableHeaderContent<TData>({
  column,
}: {
  column: VpwDataTableColumn<TData>
}) {
  if (!column.sort) return <>{column.header}</>

  const Icon = column.sort.active
    ? column.sort.direction === "asc"
      ? ArrowUp
      : ArrowDown
    : ArrowUpDown

  return (
    <Button
      aria-label={`Sort by ${column.sort.label}`}
      aria-pressed={column.sort.active}
      className="vpw-table-sort-button"
      onClick={column.sort.onSort}
      size="xs"
      type="button"
      variant="ghost"
    >
      <Icon aria-hidden="true" className="vpw-table-sort-button__icon" />
      <span>{column.header}</span>
    </Button>
  )
}
