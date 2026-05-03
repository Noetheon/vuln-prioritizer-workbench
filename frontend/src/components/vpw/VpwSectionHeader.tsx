import type { ReactNode } from "react"

export type VpwSectionHeaderProps = {
  title: string
  actions?: ReactNode
  description?: string
  eyebrow?: string
}

export function VpwSectionHeader({
  actions,
  description,
  eyebrow,
  title,
}: VpwSectionHeaderProps) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow ? (
          <p className="vpw-label text-[var(--vpw-teal)]">{eyebrow}</p>
        ) : null}
        <h2 className="mt-1 text-2xl font-semibold text-[var(--vpw-text-primary)]">
          {title}
        </h2>
        {description ? (
          <p className="mt-1 max-w-3xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
            {description}
          </p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 gap-2">{actions}</div> : null}
    </div>
  )
}
