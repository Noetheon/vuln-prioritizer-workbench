import { cn } from "@/lib/utils"
import type { VpwDataTableColumn } from "./VpwDataTable"

export function VpwDataTableMobileCards<TData>({
  ariaLabel,
  caption,
  columns,
  data,
  getRowKey,
}: {
  ariaLabel?: string
  caption?: string
  columns: readonly VpwDataTableColumn<TData>[]
  data: readonly TData[]
  getRowKey: (row: TData, index: number) => string
}) {
  const [primaryColumn, ...detailColumns] = columns

  return (
    <section
      aria-label={`${ariaLabel ?? caption ?? "Data table"} cards`}
      className="vpw-table-mobile-cards"
    >
      {data.length > 0 ? (
        <div className="vpw-table-mobile-card-list">
          {data.map((row, index) => (
            <article
              className="vpw-table-mobile-card"
              key={getRowKey(row, index)}
            >
              {primaryColumn ? (
                <div className="vpw-table-mobile-card__primary">
                  {primaryColumn.cell(row)}
                </div>
              ) : null}
              <div className="vpw-table-mobile-card__rows">
                {detailColumns.map((column) => (
                  <div
                    className={cn(
                      "vpw-table-mobile-card__row",
                      column.id.toLowerCase().includes("action")
                        ? "vpw-table-mobile-card__row--actions"
                        : undefined,
                    )}
                    key={column.id}
                  >
                    <span className="vpw-table-mobile-card__label">
                      {column.header}
                    </span>
                    <div className="vpw-table-mobile-card__value">
                      {column.cell(row)}
                    </div>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="vpw-table-mobile-card vpw-table-mobile-card--empty">
          No records available.
        </div>
      )}
    </section>
  )
}
