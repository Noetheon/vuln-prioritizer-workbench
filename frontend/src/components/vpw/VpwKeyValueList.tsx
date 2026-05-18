import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

import { VpwBadge, type VpwBadgeTone } from "./VpwBadge"

export type VpwKeyValueItem = {
  label: string
  value: ReactNode
  description?: ReactNode
  tone?: VpwBadgeTone
}

export type VpwKeyValueListProps = {
  items: readonly VpwKeyValueItem[]
  className?: string
  columns?: 1 | 2
  density?: "default" | "compact"
}

export function VpwKeyValueList({
  className,
  columns = 1,
  density = "default",
  items,
}: VpwKeyValueListProps) {
  return (
    <dl
      className={cn(
        "grid gap-3 text-sm",
        columns === 2 && "md:grid-cols-2",
        className,
      )}
    >
      {items.map((item) => (
        <div
          className={cn(
            "rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)]",
            density === "compact" ? "px-3 py-2.5" : "p-4",
          )}
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd
            className={cn(
              "min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
              density === "compact" ? "mt-1 text-sm" : "mt-2",
            )}
          >
            {item.tone ? (
              <VpwBadge tone={item.tone}>{item.value}</VpwBadge>
            ) : (
              item.value
            )}
          </dd>
          {item.description ? (
            <dd className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
              {item.description}
            </dd>
          ) : null}
        </div>
      ))}
    </dl>
  )
}
