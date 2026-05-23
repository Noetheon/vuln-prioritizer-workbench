import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type VpwSectionHeaderProps = {
  actions?: ReactNode
  className?: string
  description?: ReactNode
  eyebrow?: string
  title: ReactNode
  titleLevel?: 2 | 3
}

export function VpwSectionHeader({
  actions,
  className,
  description,
  eyebrow,
  title,
  titleLevel = 2,
}: VpwSectionHeaderProps) {
  const TitleTag = titleLevel === 2 ? "h2" : "h3"

  return (
    <div
      className={cn(
        "vpw-section-header flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between",
        className,
      )}
    >
      <div className="min-w-0">
        {eyebrow ? (
          <p className="vpw-label vpw-section-header__eyebrow">{eyebrow}</p>
        ) : null}
        <TitleTag className="vpw-section-header__title">{title}</TitleTag>
        {description ? (
          <p className="vpw-section-header__description">{description}</p>
        ) : null}
      </div>
      {actions ? (
        <div className="flex min-w-0 flex-wrap gap-2 sm:shrink-0 sm:justify-end">
          {actions}
        </div>
      ) : null}
    </div>
  )
}
