import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

import { VpwToolbar, VpwToolbarGroup } from "./VpwToolbar"
import { VpwSearchInput } from "./VpwSearchInput"

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
        <VpwSearchInput
          aria-label={searchLabel}
          className={cn("min-w-56 flex-1")}
          onChange={(event) => onSearchChange?.(event.target.value)}
          placeholder={searchPlaceholder}
          value={searchValue}
        />
        {children}
      </VpwToolbarGroup>
      {actions ? <VpwToolbarGroup>{actions}</VpwToolbarGroup> : null}
    </VpwToolbar>
  )
}
