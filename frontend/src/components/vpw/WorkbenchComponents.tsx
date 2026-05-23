import {
  isValidElement,
  type ComponentPropsWithoutRef,
  type ReactNode,
} from "react"

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

import { VpwBadge, type BadgeDensity, type VpwBadgeTone } from "./VpwBadge"
import {
  VpwDataTable,
  type VpwDataTableColumn,
  type VpwDataTableDensity,
  type VpwDataTableSort,
  type VpwDataTableVariant,
} from "./VpwDataTable"
import { VpwEmptyState, type VpwEmptyStateProps } from "./VpwEmptyState"
import { VpwFilterBar, type VpwFilterBarProps } from "./VpwFilterBar"
import {
  VpwCompactMetric,
  type VpwCompactTone,
  VpwMetricStrip,
  VpwSection,
} from "./VpwLayout"
import { VpwSectionHeader } from "./VpwSectionHeader"
import { VpwSkeletonStack } from "./VpwSkeletonStack"
import {
  VpwStatusBanner,
  type VpwStatusBannerProps,
  type VpwStatusBannerTone,
} from "./VpwStatusBanner"
import { VpwTableCard } from "./VpwTableCard"
import {
  type SignalKind,
  type StatusKind,
  signalLabel,
  signalTone,
  statusLabel,
  statusTone,
} from "./semantic-badge-model"

export type PageHeaderProps = Omit<
  ComponentPropsWithoutRef<"header">,
  "title"
> & {
  actions?: ReactNode
  context?: ReactNode
  description?: ReactNode
  eyebrow?: ReactNode
  status?: ReactNode
  title: ReactNode
}

export function PageHeader({
  actions,
  className,
  context,
  description,
  eyebrow,
  status,
  title,
  ...props
}: PageHeaderProps) {
  return (
    <header
      className={cn(
        "flex min-w-0 flex-col gap-3 border-b border-[var(--vpw-border-subtle)] pb-4",
        className,
      )}
      {...props}
    >
      <div className="flex min-w-0 flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          {eyebrow ? <p className="vpw-label">{eyebrow}</p> : null}
          <h1 className="mt-1 text-2xl font-semibold leading-tight text-[var(--vpw-text-primary)]">
            {title}
          </h1>
          {description ? (
            <p className="mt-1 max-w-3xl text-sm leading-6 text-[var(--vpw-text-secondary)]">
              {description}
            </p>
          ) : null}
        </div>
        {actions || status ? (
          <div className="flex min-w-0 flex-wrap items-center gap-2 lg:justify-end">
            {status}
            {actions}
          </div>
        ) : null}
      </div>
      {context ? <div className="min-w-0">{context}</div> : null}
    </header>
  )
}

export type ContextBarItem = {
  label: string
  value: ReactNode
  description?: ReactNode
  id?: string
  signal?: SignalBadgeProps
  status?: StatusBadgeProps
}

export type ContextBarProps = Omit<
  ComponentPropsWithoutRef<"section">,
  "title"
> & {
  actions?: ReactNode
  description?: ReactNode
  items?: readonly ContextBarItem[]
  title?: ReactNode
}

export function ContextBar({
  actions,
  children,
  className,
  description,
  items = [],
  title,
  ...props
}: ContextBarProps) {
  return (
    <section
      aria-label={typeof title === "string" ? title : "Workbench context"}
      className={cn(
        "vpw-panel flex min-w-0 flex-col gap-3 p-[var(--vpw-panel-padding)]",
        className,
      )}
      {...props}
    >
      {title || description || actions ? (
        <div className="flex min-w-0 flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0">
            {title ? (
              <h2 className="text-base font-semibold leading-tight text-[var(--vpw-text-primary)]">
                {title}
              </h2>
            ) : null}
            {description ? (
              <p className="mt-1 max-w-3xl text-sm leading-5 text-[var(--vpw-text-secondary)]">
                {description}
              </p>
            ) : null}
          </div>
          {actions ? (
            <div className="flex min-w-0 flex-wrap items-center gap-2 md:justify-end">
              {actions}
            </div>
          ) : null}
        </div>
      ) : null}
      {items.length > 0 ? (
        <div className="grid min-w-0 gap-2 md:grid-cols-2 xl:grid-cols-4">
          {items.map((item) => (
            <div
              className="min-w-0 border-t border-[var(--vpw-border-subtle)] pt-2 first:border-t-0 first:pt-0 md:first:border-t md:first:pt-2"
              key={item.id ?? item.label}
            >
              <p className="vpw-label">{item.label}</p>
              <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2">
                <div className="min-w-0 text-sm font-medium leading-5 text-[var(--vpw-text-primary)] [overflow-wrap:anywhere]">
                  {item.value}
                </div>
                {item.status ? <StatusBadge {...item.status} /> : null}
                {item.signal ? <SignalBadge {...item.signal} /> : null}
              </div>
              {item.description ? (
                <p className="mt-1 text-xs leading-5 text-[var(--vpw-text-muted)]">
                  {item.description}
                </p>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
      {children ? <div className="min-w-0">{children}</div> : null}
    </section>
  )
}

export type MetricStripMetric = {
  ariaLabel?: string
  label: string
  value: ReactNode
  description?: ReactNode
  icon?: ReactNode
  tone?: VpwCompactTone
}

export type MetricStripProps = Omit<
  ComponentPropsWithoutRef<"section">,
  "children"
> & {
  loading?: boolean
  loadingCardClassName?: string
  loadingCount?: number
  maxCardWidth?: string
  maxVisible?: 3 | 4 | 5
  metrics: readonly MetricStripMetric[]
  minCardWidth?: string
}

export function MetricStrip({
  className,
  loading = false,
  loadingCardClassName,
  loadingCount,
  maxCardWidth,
  maxVisible = 5,
  metrics,
  minCardWidth = "10rem",
  ...props
}: MetricStripProps) {
  const visibleMetrics = metrics.slice(0, maxVisible)
  const loadingSlotKeys = Array.from(
    { length: loadingCount ?? Math.max(visibleMetrics.length, 3) },
    (_, index) => `metric-loading-slot-${index + 1}`,
  )

  return (
    <VpwMetricStrip
      className={cn("workbench-metric-strip", className)}
      maxCardWidth={maxCardWidth}
      minCardWidth={minCardWidth}
      {...props}
    >
      {loading
        ? loadingSlotKeys.map((slotKey) => (
            <Skeleton
              className={cn("h-[4.5rem]", loadingCardClassName)}
              key={slotKey}
            />
          ))
        : visibleMetrics.map((metric) => (
            <VpwCompactMetric
              aria-label={metric.ariaLabel}
              description={metric.description}
              icon={metric.icon}
              key={metric.label}
              label={metric.label}
              tone={metric.tone}
              value={metric.value}
            />
          ))}
    </VpwMetricStrip>
  )
}

export type PageSectionProps = Omit<
  ComponentPropsWithoutRef<"section">,
  "title"
> & {
  actions?: ReactNode
  bodyClassName?: string
  description?: ReactNode
  eyebrow?: string
  footer?: ReactNode
  title?: ReactNode
  titleLevel?: 2 | 3
}

export function PageSection({
  actions,
  bodyClassName,
  children,
  className,
  description,
  eyebrow,
  footer,
  title,
  titleLevel = 2,
  ...props
}: PageSectionProps) {
  return (
    <VpwSection className={cn("workbench-page-section", className)} {...props}>
      {title ? (
        <VpwSectionHeader
          actions={actions}
          description={description}
          eyebrow={eyebrow}
          title={title}
          titleLevel={titleLevel}
        />
      ) : actions ? (
        <div className="flex min-w-0 flex-wrap justify-end gap-2">
          {actions}
        </div>
      ) : null}
      <div className={cn("min-w-0", bodyClassName)}>{children}</div>
      {footer ? (
        <div className="min-w-0 border-t border-[var(--vpw-border-subtle)] pt-3">
          {footer}
        </div>
      ) : null}
    </VpwSection>
  )
}

export type FilterBarProps = VpwFilterBarProps & {
  resetAction?: ReactNode
  resultCount?: number | string
  resultLabel?: ReactNode
}

export function FilterBar({
  actions,
  resetAction,
  resultCount,
  resultLabel,
  ...props
}: FilterBarProps) {
  const resolvedActions =
    resultCount !== undefined || resultLabel || resetAction || actions ? (
      <>
        {resultCount !== undefined || resultLabel ? (
          <span className="vpw-label whitespace-nowrap">
            {resultLabel ?? `${resultCount} shown`}
          </span>
        ) : null}
        {resetAction}
        {actions}
      </>
    ) : undefined

  return <VpwFilterBar actions={resolvedActions} {...props} />
}

export type DataTableFrameEmptyStateConfig = Pick<
  VpwEmptyStateProps,
  "action" | "ariaLabel" | "description" | "icon" | "title"
>

export type DataTableFrameEmptyState =
  | ReactNode
  | DataTableFrameEmptyStateConfig

export type DataTableFrameProps<TData> = Omit<
  ComponentPropsWithoutRef<"div">,
  "title"
> & {
  actions?: ReactNode
  ariaLabel?: string
  bodyClassName?: string
  caption?: string
  columns: readonly VpwDataTableColumn<TData>[]
  data?: readonly TData[]
  density?: VpwDataTableDensity
  description?: ReactNode
  emptyState?: DataTableFrameEmptyState
  eyebrow?: string
  filters?: ReactNode
  footer?: ReactNode
  getRowClassName?: (row: TData, index: number) => string | undefined
  getRowKey: (row: TData, index: number) => string
  loading?: boolean
  loadingState?: ReactNode
  minWidth?: string
  mobileCards?: boolean
  pagination?: ReactNode
  rowClassName?: string
  tableClassName?: string
  title: ReactNode
  titleLevel?: 2 | 3
  variant?: VpwDataTableVariant
}

export function DataTableFrame<TData>({
  actions,
  ariaLabel,
  bodyClassName,
  caption,
  className,
  columns,
  data = [],
  density = "standard",
  description,
  emptyState,
  eyebrow,
  filters,
  footer,
  getRowClassName,
  getRowKey,
  loading = false,
  loadingState,
  minWidth,
  mobileCards = true,
  pagination,
  rowClassName,
  tableClassName,
  title,
  titleLevel = 2,
  variant = "default",
  ...props
}: DataTableFrameProps<TData>) {
  return (
    <VpwTableCard
      actions={actions}
      bodyClassName={cn("workbench-data-table-frame__body", bodyClassName)}
      className={cn("workbench-data-table-frame", className)}
      description={description}
      eyebrow={eyebrow}
      title={title}
      titleLevel={titleLevel}
      {...props}
    >
      {filters}
      {loading ? (
        (loadingState ?? <VpwSkeletonStack rows={5} />)
      ) : (
        <VpwDataTable
          ariaLabel={ariaLabel}
          caption={caption}
          columns={columns}
          data={data}
          density={density}
          emptyState={resolveEmptyState(emptyState)}
          getRowClassName={getRowClassName}
          getRowKey={getRowKey}
          minWidth={minWidth}
          mobileCards={mobileCards}
          rowClassName={rowClassName}
          tableClassName={tableClassName}
          variant={variant}
        />
      )}
      {pagination ? (
        <div className="flex min-w-0 flex-wrap items-center justify-between gap-2 border-t border-[var(--vpw-border-subtle)] pt-3">
          {pagination}
        </div>
      ) : null}
      {footer ? <div className="min-w-0">{footer}</div> : null}
    </VpwTableCard>
  )
}

function resolveEmptyState(emptyState: DataTableFrameEmptyState | undefined) {
  if (emptyState === undefined) {
    return (
      <EmptyState
        description="Adjust filters or import supplied evidence to populate this table."
        title="No records"
      />
    )
  }
  if (isEmptyStateConfig(emptyState)) {
    return <EmptyState {...emptyState} />
  }
  return emptyState as ReactNode
}

function isEmptyStateConfig(
  value: DataTableFrameEmptyState,
): value is DataTableFrameEmptyStateConfig {
  return (
    typeof value === "object" &&
    value !== null &&
    !isValidElement(value) &&
    "title" in value
  )
}

export type StatusBadgeProps = {
  className?: string
  density?: BadgeDensity
  label?: string
  status: StatusKind | string | null | undefined
  title?: string
}

export function StatusBadge({
  className,
  density = "compact",
  label,
  status,
  title,
}: StatusBadgeProps) {
  return (
    <VpwBadge
      className={cn("vpw-semantic-badge vpw-semantic-badge--status", className)}
      density={density}
      title={title}
      tone={statusTone(status)}
    >
      {label ?? statusLabel(status)}
    </VpwBadge>
  )
}

export type SignalBadgeKind =
  | SignalKind
  | "exposure"
  | "accepted-risk"
  | "accepted_risk"
  | "provider-freshness"
  | "provider_freshness"
  | string

export type SignalBadgeProps = {
  className?: string
  density?: BadgeDensity
  kind: SignalBadgeKind
  label?: string
  title?: string
  value?: string | number | null
}

export function SignalBadge({
  className,
  density = "compact",
  kind,
  label,
  title,
  value,
}: SignalBadgeProps) {
  return (
    <VpwBadge
      className={cn("vpw-semantic-badge vpw-semantic-badge--signal", className)}
      density={density}
      title={title}
      tone={canonicalSignalTone(kind, value)}
    >
      {label ?? canonicalSignalLabel(kind, value)}
    </VpwBadge>
  )
}

function canonicalSignalLabel(
  kind: SignalBadgeKind,
  value?: string | number | null,
) {
  const normalized = normalizeSignalName(kind)
  if (normalized === "exposure") return value ? `Exposure ${value}` : "Exposure"
  if (normalized === "accepted_risk") return "Accepted risk"
  if (normalized === "provider_freshness") {
    return value ? `Freshness ${value}` : "Provider freshness"
  }
  return signalLabel({ kind, value })
}

function canonicalSignalTone(
  kind: SignalBadgeKind,
  value?: string | number | null,
): VpwBadgeTone {
  const normalized = normalizeSignalName(kind)
  if (normalized === "accepted_risk") return "success"
  if (normalized === "exposure") return "warning"
  if (normalized === "provider_freshness") {
    const freshness = normalizeSignalName(String(value ?? ""))
    if (freshness === "fresh" || freshness === "ready") return "success"
    if (freshness === "stale" || freshness === "degraded") return "warning"
    if (freshness === "failed") return "critical"
    return "info"
  }
  return signalTone(kind)
}

function normalizeSignalName(value: string) {
  return value.trim().toLowerCase().replaceAll("-", "_").replace(/\s+/g, "_")
}

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

export type EmptyStateProps = VpwEmptyStateProps

export function EmptyState(props: EmptyStateProps) {
  return <VpwEmptyState {...props} />
}

export type CalloutProps = Omit<VpwStatusBannerProps, "tone"> & {
  severity?: VpwStatusBannerTone
}

export function Callout({ severity = "info", ...props }: CalloutProps) {
  return <VpwStatusBanner tone={severity} {...props} />
}

export type {
  VpwDataTableColumn as DataTableColumn,
  VpwDataTableDensity as DataTableDensity,
  VpwDataTableSort as DataTableSort,
  VpwDataTableVariant as DataTableVariant,
}

function hasRenderableNode(value: ReactNode) {
  return value !== null && value !== undefined && typeof value !== "boolean"
}
