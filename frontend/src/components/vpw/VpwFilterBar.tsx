import { Search } from "lucide-react"
import type { ReactNode } from "react"

import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

import { VpwToolbar, VpwToolbarGroup } from "./VpwToolbar"

export type VpwFilterBarProps = {
  actions?: ReactNode
  children?: ReactNode
  className?: string
  searchLabel?: string
  searchPlaceholder?: string
  searchValue?: string
  onSearchChange?: (value: string) => void
}

export function VpwFilterBar({
  actions,
  children,
  className,
  onSearchChange,
  searchLabel = "Search",
  searchPlaceholder = "Search findings, assets, services",
  searchValue,
}: VpwFilterBarProps) {
  return (
    <VpwToolbar className={className} label="Filters">
      <VpwToolbarGroup className="flex-1">
        <div className="relative min-w-56 flex-1">
          <Search
            aria-hidden="true"
            className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--vpw-text-muted)]"
          />
          <Input
            aria-label={searchLabel}
            className={cn("pl-9")}
            onChange={(event) => onSearchChange?.(event.target.value)}
            placeholder={searchPlaceholder}
            value={searchValue}
          />
        </div>
        {children}
      </VpwToolbarGroup>
      {actions ? <VpwToolbarGroup>{actions}</VpwToolbarGroup> : null}
    </VpwToolbar>
  )
}
