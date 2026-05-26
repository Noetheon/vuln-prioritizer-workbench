import type { ComponentPropsWithoutRef, ReactNode } from "react"

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { cn } from "@/lib/utils"

import { VpwBadge, type VpwBadgeTone } from "./VpwBadge"
import {
  SignalBadge,
  type SignalBadgeProps,
  StatusBadge,
  type StatusBadgeProps,
} from "./WorkbenchBadges"

export type DefinitionListItem = {
  label: string
  value: ReactNode
  description?: ReactNode
  id?: string
  tone?: VpwBadgeTone
}

export type DefinitionListProps = {
  className?: string
  columns?: 1 | 2
  density?: "default" | "compact"
  items: readonly DefinitionListItem[]
}

export function DefinitionList({
  className,
  columns = 1,
  density = "compact",
  items,
}: DefinitionListProps) {
  return (
    <dl
      className={cn(
        "grid min-w-0 overflow-hidden rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] text-sm",
        columns === 2 && "md:grid-cols-2",
        className,
      )}
    >
      {items.map((item) => (
        <div
          className={cn(
            "min-w-0 border-t border-[var(--vpw-border-subtle)] first:border-t-0",
            density === "compact" ? "px-3 py-2" : "px-4 py-3",
          )}
          key={item.id ?? item.label}
        >
          <dt className="vpw-label">{item.label}</dt>
          <dd
            className={cn(
              "min-w-0 font-medium text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]",
              density === "compact" ? "mt-1 text-sm" : "mt-1.5 text-base",
            )}
          >
            {item.tone ? (
              <VpwBadge density="compact" tone={item.tone}>
                {item.value}
              </VpwBadge>
            ) : (
              item.value
            )}
          </dd>
          {item.description ? (
            <dd className="mt-1 text-xs leading-5 text-[var(--vpw-text-secondary)]">
              {item.description}
            </dd>
          ) : null}
        </div>
      ))}
    </dl>
  )
}

export type DecisionSummaryProps = Omit<
  ComponentPropsWithoutRef<"section">,
  "title"
> & {
  actions?: ReactNode
  decisionBasis?: ReactNode
  evidence?: ReactNode
  primaryDriver?: ReactNode
  recommendedAction?: ReactNode
  riskScore?: ReactNode
  status?: ReactNode
  title?: ReactNode
  whyThisPriority?: ReactNode
}

export function DecisionSummary({
  actions,
  className,
  decisionBasis,
  evidence,
  primaryDriver,
  recommendedAction,
  riskScore,
  status,
  title = "Decision summary",
  whyThisPriority,
  ...props
}: DecisionSummaryProps) {
  const items: DefinitionListItem[] = []
  if (hasRenderableNode(recommendedAction)) {
    items.push({ label: "Recommended action", value: recommendedAction })
  }
  if (hasRenderableNode(riskScore)) {
    items.push({ label: "Risk score", value: riskScore })
  }
  if (hasRenderableNode(primaryDriver)) {
    items.push({ label: "Primary driver", value: primaryDriver })
  }
  if (hasRenderableNode(decisionBasis)) {
    items.push({ label: "Decision basis", value: decisionBasis })
  }

  return (
    <section
      className={cn(
        "vpw-panel flex min-w-0 flex-col gap-4 p-[var(--vpw-panel-padding)]",
        className,
      )}
      {...props}
    >
      <div className="flex min-w-0 flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <p className="vpw-label">Rationale</p>
          <h2 className="mt-1 text-base font-semibold leading-tight text-[var(--vpw-text-primary)]">
            {title}
          </h2>
        </div>
        {status || actions ? (
          <div className="flex min-w-0 flex-wrap items-center gap-2 md:justify-end">
            {status}
            {actions}
          </div>
        ) : null}
      </div>
      {whyThisPriority ? (
        <div className="rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-panel)] px-3 py-2.5 text-sm leading-6 text-[var(--vpw-text-secondary)]">
          <span className="font-semibold text-[var(--vpw-text-primary)]">
            Why this priority:{" "}
          </span>
          {whyThisPriority}
        </div>
      ) : null}
      {items.length > 0 ? <DefinitionList columns={2} items={items} /> : null}
      {evidence ? (
        <div className="min-w-0 border-t border-[var(--vpw-border-subtle)] pt-3">
          {evidence}
        </div>
      ) : null}
    </section>
  )
}

export type EvidenceRowProps = ComponentPropsWithoutRef<"article"> & {
  actions?: ReactNode
  artifact?: ReactNode
  caveat?: ReactNode
  confidence?: ReactNode
  description?: ReactNode
  provider?: ReactNode
  signal?: SignalBadgeProps
  source: ReactNode
  status?: StatusBadgeProps
  timestamp?: ReactNode
  title?: ReactNode
}

export function EvidenceRow({
  actions,
  artifact,
  caveat,
  className,
  confidence,
  description,
  provider,
  signal,
  source,
  status,
  timestamp,
  title,
  ...props
}: EvidenceRowProps) {
  return (
    <article
      className={cn(
        "flex min-w-0 flex-col gap-2 border-b border-[var(--vpw-border-subtle)] py-3 last:border-b-0",
        className,
      )}
      {...props}
    >
      <div className="flex min-w-0 flex-col gap-2 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <p className="vpw-label">{source}</p>
          {title ? (
            <h3 className="mt-1 text-sm font-semibold leading-5 text-[var(--vpw-text-primary)]">
              {title}
            </h3>
          ) : null}
          {description ? (
            <div className="mt-1 text-sm leading-6 text-[var(--vpw-text-secondary)]">
              {description}
            </div>
          ) : null}
        </div>
        {actions || status || signal ? (
          <div className="flex min-w-0 flex-wrap items-center gap-2 md:justify-end">
            {status ? <StatusBadge {...status} /> : null}
            {signal ? <SignalBadge {...signal} /> : null}
            {actions}
          </div>
        ) : null}
      </div>
      {timestamp || provider || artifact || confidence ? (
        <div className="flex min-w-0 flex-wrap gap-x-4 gap-y-1 text-xs leading-5 text-[var(--vpw-text-muted)]">
          {provider ? <span>Provider: {provider}</span> : null}
          {timestamp ? <span>Timestamp: {timestamp}</span> : null}
          {artifact ? <span>Artifact: {artifact}</span> : null}
          {confidence ? <span>Confidence: {confidence}</span> : null}
        </div>
      ) : null}
      {caveat ? (
        <p className="text-xs leading-5 text-[var(--vpw-text-secondary)]">
          {caveat}
        </p>
      ) : null}
    </article>
  )
}

export type DetailRailProps = Omit<
  ComponentPropsWithoutRef<"aside">,
  "title"
> & {
  actions?: ReactNode
  description?: ReactNode
  footer?: ReactNode
  status?: ReactNode
  title?: ReactNode
}

export function DetailRail({
  actions,
  children,
  className,
  description,
  footer,
  status,
  title,
  ...props
}: DetailRailProps) {
  return (
    <aside
      className={cn(
        "vpw-panel flex min-w-0 flex-col gap-4 p-[var(--vpw-panel-padding)]",
        className,
      )}
      {...props}
    >
      {title || description || status || actions ? (
        <div className="flex min-w-0 flex-col gap-3">
          <div className="min-w-0">
            {title ? (
              <h2 className="text-base font-semibold leading-tight text-[var(--vpw-text-primary)]">
                {title}
              </h2>
            ) : null}
            {description ? (
              <p className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
                {description}
              </p>
            ) : null}
          </div>
          {status || actions ? (
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              {status}
              {actions}
            </div>
          ) : null}
        </div>
      ) : null}
      <div className="min-w-0">{children}</div>
      {footer ? (
        <div className="min-w-0 border-t border-[var(--vpw-border-subtle)] pt-3">
          {footer}
        </div>
      ) : null}
    </aside>
  )
}

export type DetailDrawerProps = {
  actions?: ReactNode
  children: ReactNode
  className?: string
  description?: ReactNode
  footer?: ReactNode
  onOpenChange?: (open: boolean) => void
  open?: boolean
  side?: "left" | "right"
  status?: ReactNode
  title: ReactNode
  trigger?: ReactNode
}

export function DetailDrawer({
  actions,
  children,
  className,
  description,
  footer,
  onOpenChange,
  open,
  side = "right",
  status,
  title,
  trigger,
}: DetailDrawerProps) {
  return (
    <Sheet onOpenChange={onOpenChange} open={open}>
      {trigger ? <SheetTrigger asChild>{trigger}</SheetTrigger> : null}
      <SheetContent
        className={cn(
          "vpw-sheet-content w-full gap-0 overflow-hidden p-0 shadow-none sm:max-w-xl",
          className,
        )}
        side={side}
      >
        <SheetHeader className="border-b border-[var(--vpw-border-subtle)] px-5 py-4 text-left">
          <div className="flex min-w-0 flex-col gap-3 pr-8">
            <div className="min-w-0">
              <SheetTitle className="text-base text-[var(--vpw-text-primary)]">
                {title}
              </SheetTitle>
              {description ? (
                <SheetDescription className="mt-1 text-sm leading-5 text-[var(--vpw-text-secondary)]">
                  {description}
                </SheetDescription>
              ) : null}
            </div>
            {status || actions ? (
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                {status}
                {actions}
              </div>
            ) : null}
          </div>
        </SheetHeader>
        <section
          aria-label="Drawer content"
          className="min-h-0 flex-1 overflow-y-auto px-5 py-4"
          // biome-ignore lint/a11y/noNoninteractiveTabindex: Scrollable drawer bodies must be keyboard-focusable.
          tabIndex={0}
        >
          {children}
        </section>
        {footer ? (
          <SheetFooter className="border-t border-[var(--vpw-border-subtle)] px-5 py-4">
            {footer}
          </SheetFooter>
        ) : null}
      </SheetContent>
    </Sheet>
  )
}

function hasRenderableNode(value: ReactNode) {
  return value !== null && value !== undefined && typeof value !== "boolean"
}
