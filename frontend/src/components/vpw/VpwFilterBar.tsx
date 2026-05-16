import { useId, type ReactNode } from "react"

import { cn } from "@/lib/utils"

import { VpwSearchInput } from "./VpwSearchInput"

export type VpwFilterBarProps = {
  actions?: ReactNode
  children?: ReactNode
  className?: string
  leading?: ReactNode
  searchClassName?: string
  searchLabel?: string
  searchPlaceholder?: string
  searchTitle?: string
  searchValue?: string
  onSearchChange?: (value: string) => void
}

export function VpwFilterBar({
  actions,
  children,
  className,
  leading,
  onSearchChange,
  searchClassName,
  searchLabel = "Search",
  searchPlaceholder = "Search findings, assets, services",
  searchTitle = "Search",
  searchValue,
}: VpwFilterBarProps) {
  const searchId = useId()

  return (
    <section
      aria-label="Filters"
      className={cn("vpw-filter-bar", className)}
    >
      {leading ? (
        <div className="vpw-filter-bar__leading">{leading}</div>
      ) : null}
      <div
        className={cn(
          "vpw-filter-field vpw-filter-field--search",
          searchClassName,
        )}
      >
        <label className="vpw-label vpw-filter-label" htmlFor={searchId}>
          {searchTitle}
        </label>
        <VpwSearchInput
          aria-label={searchLabel}
          id={searchId}
          onChange={(event) => onSearchChange?.(event.target.value)}
          placeholder={searchPlaceholder}
          value={searchValue}
        />
      </div>
      {children ? (
        <div className="vpw-filter-bar__controls">{children}</div>
      ) : null}
      {actions ? (
        <div className="vpw-filter-bar__actions">{actions}</div>
      ) : null}
    </section>
  )
}
