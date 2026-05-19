import type { ReactNode } from "react"
import type { ParserPreview } from "@/lib/import-format-metadata"
import { cn } from "@/lib/utils"

export function PreviewSummary({ parserPreview }: { parserPreview: ParserPreview }) {
  const items: Array<{ label: string; tone?: "warning"; value: ReactNode }> = [
    {
      label: "Candidate findings",
      value: parserPreview.candidateRows ?? "Available after import",
    },
    { label: "Updated findings", value: "Available after import" },
    {
      label: "Ignored lines",
      value: parserPreview.ignoredRows ?? "Available after import",
    },
    {
      label: "Warnings",
      tone: parserPreview.warnings.length > 0 ? "warning" : undefined,
      value: parserPreview.warnings.length,
    },
  ]
  return (
    <dl className="mt-3 grid gap-px overflow-hidden rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-border-subtle)] text-sm sm:grid-cols-2">
      {items.map((item) => (
        <div
          className="grid min-h-16 gap-1 bg-[var(--vpw-bg-card)] px-3 py-2.5"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd
            className={cn(
              "min-w-0 text-base font-semibold leading-5 text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
              item.tone === "warning" && "text-[var(--vpw-amber)]",
            )}
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}
