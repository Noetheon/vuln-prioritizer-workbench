import { ChevronRight } from "lucide-react"

import { cn } from "@/lib/utils"

export type VpwBreadcrumbItem = {
  label: string
  current?: boolean
}

export type VpwBreadcrumbsProps = {
  items: readonly VpwBreadcrumbItem[]
  className?: string
}

export function VpwBreadcrumbs({ className, items }: VpwBreadcrumbsProps) {
  return (
    <nav aria-label="Breadcrumb" className={cn("flex min-w-0", className)}>
      <ol className="flex min-w-0 flex-wrap items-center gap-1 text-sm">
        {items.map((item, index) => (
          <li className="flex min-w-0 items-center gap-1" key={item.label}>
            {index > 0 ? (
              <ChevronRight
                aria-hidden="true"
                className="h-3.5 w-3.5 shrink-0 text-[var(--vpw-text-muted)]"
              />
            ) : null}
            <span
              aria-current={item.current ? "page" : undefined}
              className={cn(
                "truncate",
                item.current
                  ? "font-medium text-[var(--vpw-text-primary)]"
                  : "text-[var(--vpw-text-muted)]",
              )}
            >
              {item.label}
            </span>
          </li>
        ))}
      </ol>
    </nav>
  )
}
