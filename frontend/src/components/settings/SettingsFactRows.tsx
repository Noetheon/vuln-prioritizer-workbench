import type { ReactNode } from "react"

import { VpwBadge, type VpwBadgeTone } from "@/components/vpw"

type SettingsFactRow = {
  label: string
  value: ReactNode
  tone?: VpwBadgeTone
}

export function SettingsFactRows({
  items,
}: {
  items: readonly SettingsFactRow[]
}) {
  return (
    <dl className="divide-y divide-[var(--vpw-border-subtle)]">
      {items.map((item) => (
        <div
          className="grid gap-1 px-5 py-3.5 sm:grid-cols-[minmax(8rem,0.38fr)_minmax(0,1fr)] sm:items-center"
          key={item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd className="min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
            {item.tone ? (
              <VpwBadge tone={item.tone}>{item.value}</VpwBadge>
            ) : (
              item.value
            )}
          </dd>
        </div>
      ))}
    </dl>
  )
}
