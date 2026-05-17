import { useState } from "react"
import type { ImportParseErrorPublic } from "@/api-client"
import {
  VpwBadge,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwSection,
} from "@/components/vpw"

export function ParserErrorsTable({
  errors,
}: {
  errors: ImportParseErrorPublic[]
}) {
  const columns: VpwDataTableColumn<ImportParseErrorPublic>[] = [
    { id: "line", header: "Line", cell: (error) => error.line ?? "Not supplied" },
    { id: "field", header: "Field", cell: (error) => error.field ?? "Not supplied" },
    { id: "value", header: "Value", cell: (error) => error.value ?? "Not supplied" },
    { id: "message", header: "Message", cell: (error) => error.message },
  ]

  return (
    <VpwDataTable
      caption="Parser errors"
      columns={columns}
      data={errors}
      getRowKey={(error, index) =>
        [error.filename, error.line, error.field, error.value, index].join(":")
      }
    />
  )
}

export function ParserErrors({
  defaultOpen = false,
  errors,
}: {
  defaultOpen?: boolean
  errors: ImportParseErrorPublic[]
}) {
  const [open, setOpen] = useState(defaultOpen)
  if (errors.length === 0) return null

  return (
    <VpwSection>
      <details
        className="rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-0)]"
        onToggle={(event) => setOpen(event.currentTarget.open)}
        open={open}
      >
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 [&::-webkit-details-marker]:hidden">
          <span className="min-w-0">
            <span className="block text-base font-semibold text-[var(--vpw-text-primary)]">
              Parser diagnostics
            </span>
            <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
              Rows rejected during parser validation.
            </span>
          </span>
          <VpwBadge tone="critical">{errors.length} issue(s)</VpwBadge>
        </summary>
        <div className="border-t border-[var(--vpw-border-default)] p-5">
          <ParserErrorsTable errors={errors} />
        </div>
      </details>
    </VpwSection>
  )
}
