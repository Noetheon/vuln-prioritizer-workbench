import { Search } from "lucide-react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwEmptyStateProps = {
  title: string
  ariaLabel?: string
  description?: string
  action?: ReactNode
  className?: string
  icon?: ReactNode
}

export function VpwEmptyState({
  action,
  ariaLabel,
  className,
  description,
  icon,
  title,
}: VpwEmptyStateProps) {
  return (
    <section
      aria-label={ariaLabel}
      className={cn("vpw-empty-state", className)}
    >
      <div className="mx-auto flex max-w-md flex-col items-center">
        <div className="mb-4 rounded-[var(--vpw-radius-lg)] bg-[var(--vpw-bg-panel)] p-3 text-[var(--vpw-text-muted)]">
          {icon ?? <Search className="h-5 w-5" aria-hidden="true" />}
        </div>
        <h3 className="text-base font-semibold text-[var(--vpw-text-primary)]">
          {title}
        </h3>
        {description ? (
          <p className="mt-2 text-sm leading-6 text-[var(--vpw-text-secondary)]">
            {description}
          </p>
        ) : null}
        {action ? <div className="mt-5">{action}</div> : null}
      </div>
    </section>
  )
}
