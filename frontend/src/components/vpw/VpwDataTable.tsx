import type { CSSProperties, ReactNode } from "react"

import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { cn } from "@/lib/utils"

export type VpwDataTableColumn<TData> = {
  id: string
  header: ReactNode
  cell: (row: TData) => ReactNode
  ariaSort?: "ascending" | "descending" | "none"
  className?: string
  headerClassName?: string
  width?: string
}

export type VpwDataTableDensity = "compact" | "standard" | "comfortable"
export type VpwDataTableVariant = "default" | "detail"

export type VpwDataTableProps<TData> = {
  columns: readonly VpwDataTableColumn<TData>[]
  data: readonly TData[]
  getRowKey: (row: TData, index: number) => string
  ariaLabel?: string
  caption?: string
  className?: string
  density?: VpwDataTableDensity
  emptyState?: ReactNode
  minWidth?: string
  rowClassName?: string
  tableClassName?: string
  variant?: VpwDataTableVariant
}

const densityClass: Record<VpwDataTableDensity, string> = {
  compact: "[&_td]:py-2 [&_th]:py-2",
  standard: "[&_td]:py-3 [&_th]:py-3",
  comfortable: "[&_td]:py-3.5 [&_th]:py-3",
}

const variantClass: Record<VpwDataTableVariant, string> = {
  default: "",
  detail: "vpw-table-detail",
}

export function VpwDataTable<TData>({
  caption,
  ariaLabel,
  className,
  columns,
  data,
  density = "standard",
  emptyState,
  getRowKey,
  minWidth,
  rowClassName,
  tableClassName,
  variant = "default",
}: VpwDataTableProps<TData>) {
  if (data.length === 0 && emptyState) {
    return <>{emptyState}</>
  }

  const tableStyle = {
    "--vpw-table-min-width":
      minWidth ?? `${Math.max(640, columns.length * 160)}px`,
  } as CSSProperties

  return (
    <section
      aria-label={ariaLabel ?? caption ?? "Data table"}
      className={cn("vpw-table-wrap", className)}
      style={tableStyle}
      // biome-ignore lint/a11y/noNoninteractiveTabindex: Data table wrappers can scroll horizontally and need keyboard access.
      tabIndex={0}
    >
      <Table
        className={cn(
          "vpw-table",
          variantClass[variant],
          densityClass[density],
          tableClassName,
        )}
        containerClassName="vpw-table-container"
      >
        {caption ? (
          <TableCaption className="sr-only">{caption}</TableCaption>
        ) : null}
        <colgroup>
          {columns.map((column) => (
            <col
              key={column.id}
              style={column.width ? { width: column.width } : undefined}
            />
          ))}
        </colgroup>
        <TableHeader>
          <TableRow>
            {columns.map((column) => (
              <TableHead
                aria-sort={column.ariaSort}
                className={cn("vpw-table-header-cell", column.headerClassName)}
                key={column.id}
                scope="col"
              >
                {column.header}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.length > 0 ? (
            data.map((row, index) => (
              <TableRow
                className={cn("vpw-table-row", rowClassName)}
                key={getRowKey(row, index)}
              >
                {columns.map((column) => (
                  <TableCell
                    className={cn(
                      "vpw-table-cell !whitespace-normal",
                      column.className,
                    )}
                    key={column.id}
                  >
                    {column.cell(row)}
                  </TableCell>
                ))}
              </TableRow>
            ))
          ) : (
            <TableRow className="vpw-table-row">
              <TableCell className="vpw-table-cell" colSpan={columns.length}>
                <div className="py-8 text-center text-sm text-[var(--vpw-text-muted)]">
                  No records available.
                </div>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </section>
  )
}
