import type { ComponentPropsWithoutRef, ReactNode } from "react"
import { ChevronDown } from "lucide-react"

import { cn } from "@/lib/utils"
import { VpwBadge, type VpwBadgeTone } from "./VpwBadge"
import { VpwPanel } from "./VpwLayout"

export type VpwPageStackProps = ComponentPropsWithoutRef<"div"> & {
  children: ReactNode
}

export type VpwTaskHeroStatusItem = {
  label: string
  value: ReactNode
  tone?: VpwBadgeTone
}

export type VpwTaskHeroProps = ComponentPropsWithoutRef<"section"> & {
  actions?: ReactNode
  children?: ReactNode
  description: ReactNode
  eyebrow?: string
  statusItems?: readonly VpwTaskHeroStatusItem[]
  title: string
}

export type VpwWorkflowStep = {
  description?: ReactNode
  label: string
  state?: "active" | "complete" | "pending" | "warning"
}

export type VpwWorkflowPanelProps = ComponentPropsWithoutRef<"section"> & {
  actions?: ReactNode
  children: ReactNode
  description?: ReactNode
  footer?: ReactNode
  outcome?: ReactNode
  steps?: readonly VpwWorkflowStep[]
  title: string
}

export type VpwAdvancedOptionsDisclosureProps =
  ComponentPropsWithoutRef<"details"> & {
    badge?: ReactNode
    children: ReactNode
    description?: ReactNode
    title: string
  }

export type VpwContextRailProps = ComponentPropsWithoutRef<"aside"> & {
  children: ReactNode
  label?: string
}

export type VpwOutcomeSummaryItem = {
  label: string
  value: ReactNode
  tone?: VpwBadgeTone
}

export type VpwOutcomeSummaryProps = ComponentPropsWithoutRef<"section"> & {
  actions?: ReactNode
  children?: ReactNode
  description?: ReactNode
  items?: readonly VpwOutcomeSummaryItem[]
  title: string
  tone?: VpwBadgeTone
}

const stepToneClass: Record<NonNullable<VpwWorkflowStep["state"]>, string> = {
  active:
    "border-[var(--vpw-color-brand-primary)] bg-[var(--vpw-surface-info)] text-[var(--vpw-color-brand-primary)]",
  complete:
    "border-[var(--vpw-color-brand-success)] bg-[var(--vpw-surface-success)] text-[var(--vpw-color-brand-success)]",
  pending:
    "border-[var(--vpw-border-default)] bg-[var(--vpw-surface-card)] text-[var(--vpw-text-muted)]",
  warning:
    "border-[var(--vpw-color-brand-warning)] bg-[var(--vpw-surface-warning)] text-[var(--vpw-color-brand-warning)]",
}

const outcomeToneClass: Record<VpwBadgeTone, string> = {
  neutral: "border-[var(--vpw-border-default)]",
  info: "border-[var(--vpw-color-brand-primary)]",
  success: "border-[var(--vpw-color-brand-success)]",
  warning: "border-[var(--vpw-color-brand-warning)]",
  critical: "border-[var(--vpw-color-brand-critical)]",
  support: "border-[var(--vpw-color-brand-support)]",
}

export function VpwPageStack({
  children,
  className,
  ...props
}: VpwPageStackProps) {
  return (
    <div className={cn("flex flex-col gap-7", className)} {...props}>
      {children}
    </div>
  )
}

export function VpwTaskHero({
  actions,
  children,
  className,
  description,
  eyebrow,
  statusItems = [],
  title,
  ...props
}: VpwTaskHeroProps) {
  return (
    <section
      className={cn(
        "vpw-panel flex flex-col gap-5 p-5 sm:p-6 xl:flex-row xl:items-end xl:justify-between",
        className,
      )}
      {...props}
    >
      <div className="min-w-0 flex-1">
        {eyebrow ? (
          <p className="mb-2 text-xs font-semibold uppercase text-[var(--vpw-color-brand-teal)]">
            {eyebrow}
          </p>
        ) : null}
        <div className="flex min-w-0 flex-col gap-2">
          <h1 className="text-2xl font-semibold leading-tight text-[var(--vpw-text-primary)] sm:text-3xl">
            {title}
          </h1>
          <p className="max-w-4xl text-base text-[var(--vpw-text-secondary)]">
            {description}
          </p>
        </div>
        {statusItems.length > 0 ? (
          <dl className="mt-5 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            {statusItems.map((item) => (
              <div
                className="min-w-0 rounded-[var(--vpw-radius-md)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-surface-panel)] px-3 py-2"
                key={item.label}
              >
                <dt className="truncate text-xs font-semibold uppercase text-[var(--vpw-text-muted)]">
                  {item.label}
                </dt>
                <dd className="mt-1 min-w-0 text-sm font-semibold text-[var(--vpw-text-primary)]">
                  {item.tone ? (
                    <VpwBadge tone={item.tone}>{item.value}</VpwBadge>
                  ) : (
                    item.value
                  )}
                </dd>
              </div>
            ))}
          </dl>
        ) : null}
        {children ? <div className="mt-5">{children}</div> : null}
      </div>
      {actions ? (
        <div className="flex shrink-0 flex-col gap-2 sm:flex-row xl:justify-end">
          {actions}
        </div>
      ) : null}
    </section>
  )
}

export function VpwWorkflowPanel({
  actions,
  children,
  className,
  description,
  footer,
  outcome,
  steps = [],
  title,
  ...props
}: VpwWorkflowPanelProps) {
  return (
    <section className={cn("flex flex-col gap-4", className)} {...props}>
      <VpwPanel className="flex flex-col gap-5 p-5 sm:p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0">
            <h2 className="text-xl font-semibold text-[var(--vpw-text-primary)]">
              {title}
            </h2>
            {description ? (
              <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
                {description}
              </p>
            ) : null}
          </div>
          {actions ? (
            <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>
          ) : null}
        </div>

        {steps.length > 0 ? (
          <ol className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {steps.map((step, index) => {
              const state = step.state ?? "pending"
              return (
                <li
                  className="flex min-w-0 gap-3 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-surface-panel)] p-3"
                  key={step.label}
                >
                  <span
                    className={cn(
                      "flex h-7 w-7 shrink-0 items-center justify-center rounded-[var(--vpw-radius-md)] border text-xs font-semibold",
                      stepToneClass[state],
                    )}
                    aria-hidden="true"
                  >
                    {index + 1}
                  </span>
                  <span className="min-w-0">
                    <span className="block text-sm font-semibold text-[var(--vpw-text-primary)]">
                      {step.label}
                    </span>
                    {step.description ? (
                      <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
                        {step.description}
                      </span>
                    ) : null}
                  </span>
                </li>
              )
            })}
          </ol>
        ) : null}

        <div>{children}</div>
        {outcome ? <div>{outcome}</div> : null}
        {footer ? (
          <div className="border-t border-[var(--vpw-border-subtle)] pt-4">
            {footer}
          </div>
        ) : null}
      </VpwPanel>
    </section>
  )
}

export function VpwAdvancedOptionsDisclosure({
  badge,
  children,
  className,
  description,
  title,
  ...props
}: VpwAdvancedOptionsDisclosureProps) {
  return (
    <details
      className={cn(
        "group rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-default)] bg-[var(--vpw-surface-panel)]",
        className,
      )}
      {...props}
    >
      <summary className="flex cursor-pointer list-none items-start justify-between gap-4 p-4 marker:content-none">
        <span className="min-w-0">
          <span className="flex flex-wrap items-center gap-2 text-sm font-semibold text-[var(--vpw-text-primary)]">
            {title}
            {badge}
          </span>
          {description ? (
            <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
              {description}
            </span>
          ) : null}
        </span>
        <ChevronDown
          className="mt-0.5 h-4 w-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-open:rotate-180"
          aria-hidden="true"
        />
      </summary>
      <div className="border-t border-[var(--vpw-border-subtle)] p-4">
        {children}
      </div>
    </details>
  )
}

export function VpwContextRail({
  children,
  className,
  label = "Context",
  ...props
}: VpwContextRailProps) {
  return (
    <aside
      aria-label={label}
      className={cn("flex min-w-0 flex-col gap-4", className)}
      {...props}
    >
      {children}
    </aside>
  )
}

export function VpwOutcomeSummary({
  actions,
  children,
  className,
  description,
  items = [],
  title,
  tone = "neutral",
  ...props
}: VpwOutcomeSummaryProps) {
  return (
    <section
      className={cn(
        "rounded-[var(--vpw-radius-lg)] border bg-[var(--vpw-surface-card)] p-4",
        outcomeToneClass[tone],
        className,
      )}
      {...props}
    >
      <div className="flex flex-col gap-3">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-[var(--vpw-text-primary)]">
              {title}
            </h3>
            {description ? (
              <p className="mt-1 text-sm text-[var(--vpw-text-secondary)]">
                {description}
              </p>
            ) : null}
          </div>
          {actions ? <div className="shrink-0">{actions}</div> : null}
        </div>
        {items.length > 0 ? (
          <dl className="grid gap-2">
            {items.map((item) => (
              <div
                className="flex min-w-0 items-center justify-between gap-3 text-sm"
                key={item.label}
              >
                <dt className="truncate text-[var(--vpw-text-secondary)]">
                  {item.label}
                </dt>
                <dd className="min-w-0 text-right font-medium text-[var(--vpw-text-primary)]">
                  {item.tone ? (
                    <VpwBadge tone={item.tone}>{item.value}</VpwBadge>
                  ) : (
                    item.value
                  )}
                </dd>
              </div>
            ))}
          </dl>
        ) : null}
        {children}
      </div>
    </section>
  )
}
