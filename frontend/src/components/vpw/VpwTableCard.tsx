import type { ComponentPropsWithoutRef, ReactNode } from "react"

import { cn } from "@/lib/utils"

import { VpwPanel } from "./VpwLayout"

export type VpwTableCardProps = Omit<
  ComponentPropsWithoutRef<"div">,
  "title"
> & {
  children: ReactNode
  actions?: ReactNode
  bodyClassName?: string
  className?: string
  description?: ReactNode
  eyebrow?: string
  title: ReactNode
  titleLevel?: 2 | 3
}

export function VpwTableCard({
  actions,
  bodyClassName,
  children,
  className,
  description,
  eyebrow,
  title,
  titleLevel = 2,
  ...props
}: VpwTableCardProps) {
  const TitleTag = titleLevel === 2 ? "h2" : "h3"

  return (
    <VpwPanel
      className={cn("vpw-table-card", className)}
      padded={false}
      {...props}
    >
      <div className="vpw-table-card__header">
        <div className="vpw-table-card__heading">
          {eyebrow ? (
            <p className="vpw-label vpw-table-card__eyebrow">{eyebrow}</p>
          ) : null}
          <TitleTag className="vpw-table-card__title">{title}</TitleTag>
          {description ? (
            <p className="vpw-table-card__description">{description}</p>
          ) : null}
        </div>
        {actions ? (
          <div className="vpw-table-card__actions">{actions}</div>
        ) : null}
      </div>
      <div className={cn("vpw-table-card__body", bodyClassName)}>
        {children}
      </div>
    </VpwPanel>
  )
}
