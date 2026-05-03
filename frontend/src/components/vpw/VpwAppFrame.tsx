import type { LucideIcon } from "lucide-react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

import { VpwBadge } from "./VpwBadge"

export type VpwNavItem = {
  icon?: LucideIcon
  label: string
  active?: boolean
}

export type VpwStatusStripItem = {
  label: string
  value: ReactNode
}

export type VpwAppFrameProps = {
  children: ReactNode
  navItems: readonly VpwNavItem[]
  title: string
  eyebrow?: string
  healthLabel?: string
  statusItems?: readonly VpwStatusStripItem[]
  userLabel?: string
}

export function VpwAppFrame({
  children,
  eyebrow = "Security Operations",
  healthLabel = "Workspace healthy",
  navItems,
  statusItems = [],
  title,
  userLabel = "admin@example.com",
}: VpwAppFrameProps) {
  return (
    <div className="grid min-h-[34rem] overflow-hidden rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-app)] shadow-[var(--vpw-shadow-3)] lg:grid-cols-[248px_1fr]">
      <aside className="hidden bg-[var(--vpw-navy)] p-4 text-white lg:block">
        <div className="flex items-center gap-3">
          <div className="grid size-9 place-items-center rounded-[var(--vpw-radius-md)] bg-[var(--vpw-amber)] font-extrabold text-[var(--vpw-text-primary)] text-xs">
            VP
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold">Vuln Prioritizer</p>
            <p className="truncate text-xs text-slate-500">Workbench</p>
          </div>
        </div>
        <nav className="mt-6 grid gap-1" aria-label="VPW app frame preview">
          {navItems.map((item) => {
            const Icon = item.icon
            return (
              <div
                className={cn(
                  "flex min-h-10 items-center gap-2.5 rounded-[var(--vpw-radius-md)] px-3 text-sm font-medium",
                  item.active ? "bg-white/10 text-white" : "text-slate-400",
                )}
                key={item.label}
              >
                {Icon ? <Icon aria-hidden="true" className="h-4 w-4" /> : null}
                <span className="truncate">{item.label}</span>
              </div>
            )
          })}
        </nav>
        <div className="mt-8 rounded-[var(--vpw-radius-md)] border border-white/10 p-3 text-xs text-slate-400">
          {userLabel}
        </div>
      </aside>
      <div className="min-w-0">
        <header className="flex items-center justify-between gap-4 border-b border-[var(--vpw-border-default)] bg-[var(--vpw-bg-page)] px-5 py-3">
          <div className="min-w-0">
            <p className="vpw-label">{eyebrow}</p>
            <h2 className="truncate text-lg font-semibold text-[var(--vpw-text-primary)]">
              {title}
            </h2>
          </div>
          <VpwBadge tone="success">{healthLabel}</VpwBadge>
        </header>
        {statusItems.length > 0 ? (
          <div className="grid border-b border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] sm:grid-cols-2 xl:grid-cols-4">
            {statusItems.map((item) => (
              <div
                className="border-b border-[var(--vpw-border-subtle)] px-5 py-3 sm:border-r xl:border-b-0"
                key={item.label}
              >
                <p className="vpw-label">{item.label}</p>
                <div className="mt-1 text-sm font-semibold text-[var(--vpw-text-primary)]">
                  {item.value}
                </div>
              </div>
            ))}
          </div>
        ) : null}
        <div className="p-5">{children}</div>
      </div>
    </div>
  )
}
