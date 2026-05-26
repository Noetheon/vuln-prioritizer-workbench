import type { ReactNode } from "react"
import { Clipboard } from "lucide-react"
import { Button } from "@/components/ui/button"
import { objectRecord } from "./imports-workbench-model"

export function CopyableValue({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex max-w-full items-center gap-2">
      <span className="min-w-0 truncate" title={value}>
        {value}
      </span>
      <CopyButton label={label} value={value} />
    </span>
  )
}

export function CopyButton({ label, value }: { label: string; value: string }) {
  return (
    <Button
      aria-label={label}
      className="shrink-0"
      onClick={() => void navigator.clipboard?.writeText(value)}
      size="icon-sm"
      type="button"
      variant="ghost"
    >
      <Clipboard aria-hidden="true" />
    </Button>
  )
}

export function CompactRows({
  items,
}: {
  items: readonly { label: string; value: ReactNode }[]
}) {
  return (
    <dl className="divide-y divide-[var(--vpw-border-subtle)] rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] text-sm">
      {items.map((item) => (
        <div
          className="grid grid-cols-[9rem_minmax(0,1fr)] gap-3 px-3 py-2"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd className="min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function stringValue(source: unknown, key: string) {
  const record = objectRecord(source)
  const value = record[key]
  if (typeof value === "string" && value.trim()) return value
  if (typeof value === "boolean") return value ? "Yes" : "No"
  return null
}

export function recordedValue(value: unknown) {
  if (typeof value === "number") return value
  if (typeof value === "string" && value.trim()) return value
  return "Not recorded"
}

export function warningCount(value: unknown) {
  const warnings = Array.isArray(value) ? value : objectRecord(value).warnings
  if (Array.isArray(warnings)) return warnings.length
  return typeof warnings === "number" ? warnings : "Not recorded"
}
