import type { ReactNode } from "react"
import { cn } from "../../lib/utils"

type AppShellStatusStripProps = {
  hideStatusStrip: boolean
  statusItems: readonly {
    label: string
    value: ReactNode
  }[]
}

export function AppShellStatusStrip({
  hideStatusStrip,
  statusItems,
}: AppShellStatusStripProps) {
  if (hideStatusStrip || statusItems.length === 0) return null

  return (
    <section
      aria-label="Workbench status summary"
      className="shrink-0 border-b border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-page)]"
    >
      <div className="grid grid-cols-2 items-stretch lg:flex lg:min-w-0">
        {statusItems.map((item, index) => (
          <div
            className={cn(
              "flex min-w-0 flex-col justify-center px-4 py-2 lg:min-w-0 lg:px-6",
              index % 2 === 1 &&
                "border-l border-[var(--vpw-border-subtle)]",
              index > 1 &&
                "border-t border-[var(--vpw-border-subtle)] lg:border-t-0",
              index > 0 &&
                "lg:border-l lg:border-[var(--vpw-border-subtle)]",
            )}
            key={item.label || index}
          >
            <span className="text-[10px] font-bold uppercase text-[var(--vpw-text-muted)]">
              {item.label}
            </span>
            <span className="mt-0.5 truncate text-sm font-semibold text-[var(--vpw-text-primary)]">
              {item.value}
            </span>
          </div>
        ))}
      </div>
    </section>
  )
}
