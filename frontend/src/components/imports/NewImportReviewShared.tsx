import type { ReactNode } from "react"
import { cn } from "@/lib/utils"

export function ReviewSectionHeading({
  description,
  title,
}: {
  description: string
  title: string
}) {
  return (
    <div>
      <h3 className="text-base font-semibold text-[var(--vpw-text-primary)]">
        {title}
      </h3>
      <p className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
        {description}
      </p>
    </div>
  )
}

export function ReviewMetric({
  label,
  tone,
  value,
}: {
  label: string
  tone?: "critical" | "success"
  value: ReactNode
}) {
  return (
    <div className="min-w-0 px-3 py-2 md:first:pl-3 md:last:pr-3">
      <dt className="vpw-label">{label}</dt>
      <dd
        className={cn(
          "mt-1 min-w-0 font-medium leading-5 text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
          tone === "success" && "text-[var(--vpw-green)]",
          tone === "critical" && "text-[var(--vpw-red)]",
        )}
      >
        {value}
      </dd>
    </div>
  )
}

export function SettingsSummaryList({
  items,
}: {
  items: readonly { label: string; muted?: boolean; value: ReactNode }[]
}) {
  return (
    <dl className="mt-3 border-t border-[var(--vpw-border-subtle)] text-sm">
      {items.map((item) => (
        <div
          className="grid gap-2 border-b border-[var(--vpw-border-subtle)] py-3 sm:grid-cols-[minmax(9rem,0.42fr)_minmax(0,1fr)]"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd
            className={cn(
              "min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
              item.muted && "text-[var(--vpw-text-secondary)]",
            )}
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}
