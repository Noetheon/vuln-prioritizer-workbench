import { Link } from "@tanstack/react-router"
import {
  AlertTriangle,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  Eye,
  FileDown,
  Filter,
  ListFilter,
  Upload,
  X,
} from "lucide-react"
import { useState } from "react"
import type {
  AssetExposure,
  FindingPriority,
  FindingPublic,
  FindingStatus,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
} from "@/api-client"
import {
  CvssBadge,
  EpssBadge,
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
} from "@/components/risk"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { TooltipProvider } from "@/components/ui/tooltip"
import {
  VpwBadge,
  VpwDemoBanner,
  VpwEmptyState,
  VpwGrid,
  VpwMetricCard,
  VpwPanel,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
} from "@/components/vpw"
import { DEMO_FINDINGS, DEMO_PROJECT, DEMO_SUMMARY } from "@/lib/demo-data"
import { DEMO_MODE_ENABLED } from "@/lib/runtime-config"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import { cn } from "@/lib/utils"
import { FindingsDataTable, type QueueSort } from "./FindingsDataTable"
import {
  activeFilterCount,
  advancedFilterCount,
  componentLabel,
  defaultSortDirections,
  exposureOptions,
  type FindingFilters,
  type FindingsDirection,
  type FindingsSort,
  isApiSort,
  pageSizeOptions,
  priorityOptions,
  riskScoreColor,
  sortDisplayFindings,
  statusOptions,
  type KevFilter,
} from "./remediation-queue-model"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RemediationQueueProps = {
  findings: FindingPublic[]
  findingsLoading: boolean
  findingsError: string
  findingCount: number
  findingOffset: number
  findingPageSize: number
  findingSort: FindingsSort
  findingDirection: FindingsDirection
  findingFilters: FindingFilters
  activeFindingFilters: boolean
  findingAssetId: string | null
  findingAssetKey: string | null
  selectedProject: ProjectPublic | null
  projects: ProjectPublic[]
  projectListLoading: boolean
  selectedProjectId: string
  projectSummary: ProjectDecisionSummaryPublic | null
  onFilterChange: <K extends keyof FindingFilters>(
    key: K,
    value: FindingFilters[K],
  ) => void
  onClearFilters: () => void
  onSortChange: (sort: FindingsSort) => void
  onDirectionChange: (direction: FindingsDirection) => void
  onPageNext: () => void
  onPagePrev: () => void
  onPageSizeChange: (size: number) => void
  onProjectChange: (id: string) => void
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function DemoBanner() {
  return (
    <VpwDemoBanner>
      <strong className="font-semibold">Demo preview</strong> - showing sample
      findings. Connect a real project to see live data.
    </VpwDemoBanner>
  )
}

type SummaryChipProps = {
  label: string
  value: number | string
  tone?: "critical" | "warning" | "info" | "support"
}

function SummaryChip({ label, value, tone = "info" }: SummaryChipProps) {
  return (
    <VpwBadge tone={tone}>
      {label}: <span className="font-bold">{value}</span>
    </VpwBadge>
  )
}

type WhyDialogProps = {
  finding: FindingPublic | null
  open: boolean
  onClose: () => void
}

function WhyDialog({ finding, open, onClose }: WhyDialogProps) {
  if (!finding) return null
  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <PriorityBadge priority={finding.priority} />
            <span className="font-mono text-sm">{finding.cve_id}</span>
          </DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4 text-sm">
          {finding.rationale ? (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                Why now
              </p>
              <p className="leading-relaxed">{finding.rationale}</p>
            </div>
          ) : (
            <p className="text-muted-foreground">
              No rationale recorded for this finding.
            </p>
          )}
          {finding.recommended_action ? (
            <div className="rounded-md border border-teal-500/30 bg-teal-500/10 p-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-teal-700 dark:text-teal-400 mb-1">
                Recommended action
              </p>
              <p className="leading-relaxed">{finding.recommended_action}</p>
            </div>
          ) : null}
          <dl className="grid grid-cols-3 gap-3 rounded-md border bg-muted/40 p-3 text-xs">
            <div>
              <dt className="text-muted-foreground">Risk Score</dt>
              <dd
                className={cn(
                  "font-bold text-sm",
                  riskScoreColor(finding.risk_score),
                )}
              >
                {finding.risk_score?.toFixed(1) ?? "N.A."}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">EPSS</dt>
              <dd className="font-semibold text-sm">
                <EpssBadge value={finding.epss} />
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">KEV</dt>
              <dd className="font-semibold text-sm">
                <KevBadge matched={finding.in_kev} />
              </dd>
            </div>
          </dl>
        </div>
      </DialogContent>
    </Dialog>
  )
}

type QuickViewSheetProps = {
  finding: FindingPublic | null
  open: boolean
  onClose: () => void
}

function QuickViewSheet({ finding, open, onClose }: QuickViewSheetProps) {
  if (!finding) return null
  return (
    <Sheet open={open} onOpenChange={(v) => !v && onClose()}>
      <SheetContent className="w-96 overflow-y-auto">
        <SheetHeader>
          <SheetTitle className="font-mono text-base">
            {finding.cve_id}
          </SheetTitle>
        </SheetHeader>
        <div className="flex flex-col gap-5 mt-6 text-sm">
          <div className="flex flex-wrap gap-2">
            <PriorityBadge priority={finding.priority} />
            <FindingStatusBadge status={finding.status} />
            <KevBadge matched={finding.in_kev} />
          </div>

          <dl className="grid grid-cols-2 gap-3">
            {[
              {
                label: "Risk Score",
                value: finding.risk_score?.toFixed(1) ?? "N.A.",
              },
              { label: "EPSS", value: <EpssBadge value={finding.epss} /> },
              {
                label: "CVSS",
                value: <CvssBadge value={finding.cvss_base_score} />,
              },
              { label: "Exposure", value: labelize(finding.exposure) },
              { label: "Owner", value: optionalText(finding.owner) },
              {
                label: "Service",
                value: optionalText(finding.business_service),
              },
            ].map(({ label, value }) => (
              <div key={label}>
                <dt className="text-xs text-muted-foreground">{label}</dt>
                <dd className="font-medium mt-0.5">{value}</dd>
              </div>
            ))}
          </dl>

          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
              Component
            </p>
            <p className="font-medium">{componentLabel(finding)}</p>
            {finding.component_purl ? (
              <p className="text-xs text-muted-foreground mt-0.5 break-all">
                {finding.component_purl}
              </p>
            ) : null}
          </div>

          {finding.rationale ? (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                Rationale
              </p>
              <p className="leading-relaxed text-sm">{finding.rationale}</p>
            </div>
          ) : null}

          {finding.recommended_action ? (
            <div className="rounded-md border border-teal-500/30 bg-teal-500/10 p-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-teal-700 dark:text-teal-400 mb-1">
                Recommended action
              </p>
              <p className="leading-relaxed text-sm">
                {finding.recommended_action}
              </p>
            </div>
          ) : null}

          <div className="pt-2 border-t">
            <Button asChild className="w-full" size="sm" variant="outline">
              <Link
                params={{ findingId: finding.id }}
                to="/findings/$findingId"
              >
                Open full detail
              </Link>
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function RemediationQueue({
  findings,
  findingsLoading,
  findingsError,
  findingCount,
  findingOffset,
  findingPageSize,
  findingSort,
  findingDirection,
  findingFilters,
  activeFindingFilters,
  findingAssetId,
  findingAssetKey,
  selectedProject,
  projects,
  projectListLoading,
  selectedProjectId,
  projectSummary,
  onFilterChange,
  onClearFilters,
  onSortChange,
  onDirectionChange,
  onPageNext,
  onPagePrev,
  onPageSizeChange,
  onProjectChange,
}: RemediationQueueProps) {
  const [whyFinding, setWhyFinding] = useState<FindingPublic | null>(null)
  const [sheetFinding, setSheetFinding] = useState<FindingPublic | null>(null)
  const [whyOpen, setWhyOpen] = useState(false)
  const [sheetOpen, setSheetOpen] = useState(false)
  const [advancedFiltersOpen, setAdvancedFiltersOpen] = useState(false)
  const [queueSort, setQueueSort] = useState<QueueSort>(findingSort)

  const isDemo =
    DEMO_MODE_ENABLED && projects.length === 0 && !projectListLoading
  const sourceFindings = isDemo ? DEMO_FINDINGS : findings
  const displayFindings = isDemo
    ? sortDisplayFindings(sourceFindings, queueSort, findingDirection)
    : sourceFindings
  const displaySummary = isDemo ? DEMO_SUMMARY : projectSummary
  const displayProject = isDemo ? DEMO_PROJECT : selectedProject
  const isLoading = !isDemo && findingsLoading
  const hasError = !isDemo && Boolean(findingsError)

  const criticalCount =
    displaySummary?.counts_by_priority?.critical ??
    displaySummary?.counts_by_priority?.Critical ??
    0
  const highCount =
    displaySummary?.counts_by_priority?.high ??
    displaySummary?.counts_by_priority?.High ??
    0
  const kevCount = displaySummary?.kev_hits ?? 0
  const openCount = displaySummary?.counts_by_status?.open ?? 0

  const pageStart = isDemo
    ? 1
    : findingCount === 0
      ? 0
      : Math.min(findingOffset + 1, findingCount)
  const pageEnd = isDemo
    ? displayFindings.length
    : Math.min(findingOffset + findings.length, findingCount)
  const totalCount = isDemo ? displayFindings.length : findingCount

  const filterCount = activeFilterCount(findingFilters, Boolean(findingAssetId))
  const signalFilterCount = advancedFilterCount(findingFilters)
  const showAdvancedFilters = advancedFiltersOpen || signalFilterCount > 0

  function openWhy(finding: FindingPublic) {
    setWhyFinding(finding)
    setWhyOpen(true)
  }
  function openSheet(finding: FindingPublic) {
    setSheetFinding(finding)
    setSheetOpen(true)
  }

  function updateColumnSort(sort: QueueSort) {
    const nextDirection =
      queueSort === sort
        ? findingDirection === "asc"
          ? "desc"
          : "asc"
        : defaultSortDirections[sort]
    setQueueSort(sort)
    if (isApiSort(sort)) {
      onSortChange(sort)
    }
    onDirectionChange(nextDirection)
  }

  return (
    <TooltipProvider>
      <div className="findings-remediation-layout flex flex-col gap-5">
        {/* Demo banner */}
        {isDemo ? <DemoBanner /> : null}

        {/* ── Hero ─────────────────────────────────────────────────── */}
        <VpwSection>
          <VpwPanel className="space-y-5 bg-[var(--vpw-bg-card)]">
            <VpwSectionHeader
              actions={
                <>
                  <Button asChild size="sm" variant="outline">
                    <Link to="/reports">
                      <FileDown
                        aria-hidden="true"
                        className="mr-1.5"
                        size={14}
                      />
                      Generate evidence
                    </Link>
                  </Button>
                  <Button asChild size="sm">
                    <Link to="/imports">
                      <Upload aria-hidden="true" className="mr-1.5" size={14} />
                      Import findings
                    </Link>
                  </Button>
                </>
              }
              description={
                displayProject?.name
                  ? `Prioritized remediation queue for ${displayProject.name}`
                  : "Prioritized remediation queue for the selected project"
              }
              eyebrow="Remediation Queue"
              title="Findings"
            />
            <VpwGrid columns={4}>
              <VpwMetricCard
                description="highest urgency"
                icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
                label="Critical"
                tone="critical"
                value={criticalCount}
              />
              <VpwMetricCard
                description="near-term action"
                icon={<ArrowUp aria-hidden="true" className="h-4 w-4" />}
                label="High"
                tone="warning"
                value={highCount}
              />
              <VpwMetricCard
                description="known exploited"
                icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
                label="KEV"
                tone="support"
                value={kevCount}
              />
              <VpwMetricCard
                description="open lifecycle"
                icon={<Eye aria-hidden="true" className="h-4 w-4" />}
                label="Open"
                tone="info"
                value={openCount}
              />
            </VpwGrid>
            <div className="flex flex-wrap gap-2">
              <SummaryChip
                label="Critical"
                tone="critical"
                value={criticalCount}
              />
              <SummaryChip label="High" tone="warning" value={highCount} />
              <SummaryChip label="KEV" tone="support" value={kevCount} />
              <SummaryChip label="Open" tone="info" value={openCount} />
            </div>
          </VpwPanel>
        </VpwSection>

        {/* ── Filter bar ───────────────────────────────────────────── */}
        <VpwPanel
          aria-label="Findings filters"
          className="findings-filter-card py-0 shadow-sm"
          role="region"
        >
          <div className="px-4 py-3">
            <div className="flex flex-wrap items-center gap-2">
              {!isDemo ? (
                <div className="flex min-w-44 flex-col gap-1">
                  <span className="text-[11px] font-semibold uppercase text-muted-foreground">
                    Project
                  </span>
                  <Select
                    disabled={projectListLoading || projects.length === 0}
                    onValueChange={(v) => {
                      onProjectChange(v)
                    }}
                    value={selectedProjectId}
                  >
                    <SelectTrigger
                      aria-label="Project"
                      className="h-9 w-48 text-sm"
                    >
                      <SelectValue placeholder="No projects" />
                    </SelectTrigger>
                    <SelectContent>
                      {projects.map((p) => (
                        <SelectItem key={p.id} value={p.id}>
                          {p.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ) : null}

              {findingAssetId ? (
                <div className="inline-flex h-9 items-center gap-1.5 rounded-md border bg-muted px-2 text-xs font-medium">
                  <span>Asset</span>
                  <strong>{findingAssetKey ?? findingAssetId}</strong>
                  <Button
                    aria-label="Clear asset filter"
                    className="ml-1 size-6"
                    onClick={onClearFilters}
                    size="icon"
                    type="button"
                    variant="ghost"
                  >
                    <X aria-hidden="true" size={12} />
                  </Button>
                </div>
              ) : null}

              <label
                className="flex min-w-56 flex-1 flex-col gap-1"
                htmlFor="queue-search"
              >
                <span className="text-[11px] font-semibold uppercase text-muted-foreground">
                  Owner / Service
                </span>
                <Input
                  className="h-9 text-sm"
                  id="queue-search"
                  onChange={(e) =>
                    onFilterChange("ownerService", e.target.value)
                  }
                  placeholder="payments, infra-team"
                  value={findingFilters.ownerService}
                />
              </label>

              <div className="flex flex-col gap-1">
                <span className="text-[11px] font-semibold uppercase text-muted-foreground">
                  Priority
                </span>
                <Select
                  onValueChange={(v) =>
                    onFilterChange(
                      "priority",
                      v === "__all" ? "" : (v as FindingPriority),
                    )
                  }
                  value={findingFilters.priority || "__all"}
                >
                  <SelectTrigger
                    aria-label="Priority"
                    className="h-9 w-32 text-sm"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all">All</SelectItem>
                    {priorityOptions.map((p) => (
                      <SelectItem key={p} value={p}>
                        {labelize(p)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex flex-col gap-1">
                <span className="text-[11px] font-semibold uppercase text-muted-foreground">
                  Status
                </span>
                <Select
                  onValueChange={(v) =>
                    onFilterChange(
                      "status",
                      v === "__all" ? "" : (v as FindingStatus),
                    )
                  }
                  value={findingFilters.status || "__all"}
                >
                  <SelectTrigger
                    aria-label="Status"
                    className="h-9 w-36 text-sm"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all">All</SelectItem>
                    {statusOptions.map((s) => (
                      <SelectItem key={s} value={s}>
                        {labelize(s)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="ml-auto flex items-end gap-2 self-end">
                <Button
                  aria-expanded={showAdvancedFilters}
                  className="h-9"
                  onClick={() => setAdvancedFiltersOpen((open) => !open)}
                  size="sm"
                  type="button"
                  variant={showAdvancedFilters ? "secondary" : "outline"}
                >
                  <ListFilter aria-hidden="true" size={14} />
                  Signals
                  {signalFilterCount > 0 ? (
                    <VpwBadge className="ml-1 h-4 min-w-4 px-1 py-0 text-[10px]">
                      {signalFilterCount}
                    </VpwBadge>
                  ) : null}
                </Button>

                <Button
                  className="h-9"
                  disabled={!activeFindingFilters && filterCount === 0}
                  onClick={onClearFilters}
                  size="sm"
                  type="button"
                  variant="ghost"
                >
                  <Filter aria-hidden="true" size={14} />
                  Reset
                </Button>
              </div>
            </div>

            {showAdvancedFilters ? (
              <div className="mt-3 flex flex-wrap items-end gap-2 border-t pt-3">
                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-semibold uppercase text-muted-foreground">
                    KEV
                  </span>
                  <Select
                    onValueChange={(v) =>
                      onFilterChange(
                        "kev",
                        v === "__all" ? "" : (v as KevFilter),
                      )
                    }
                    value={findingFilters.kev || "__all"}
                  >
                    <SelectTrigger
                      aria-label="KEV"
                      className="h-9 w-28 text-sm"
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__all">Any</SelectItem>
                      <SelectItem value="true">KEV</SelectItem>
                      <SelectItem value="false">Not KEV</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-semibold uppercase text-muted-foreground">
                    Exposure
                  </span>
                  <Select
                    onValueChange={(v) =>
                      onFilterChange(
                        "exposure",
                        v === "__all" ? "" : (v as AssetExposure),
                      )
                    }
                    value={findingFilters.exposure || "__all"}
                  >
                    <SelectTrigger
                      aria-label="Exposure"
                      className="h-9 w-40 text-sm"
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__all">Any</SelectItem>
                      {exposureOptions.map((e) => (
                        <SelectItem key={e} value={e}>
                          {labelize(e)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-semibold uppercase text-muted-foreground">
                    EPSS
                  </span>
                  <div className="flex items-center gap-1">
                    <Input
                      aria-label="EPSS min"
                      className="h-9 w-20 text-sm"
                      inputMode="decimal"
                      max="1"
                      min="0"
                      onChange={(e) =>
                        onFilterChange("epssMin", e.target.value)
                      }
                      placeholder="Min"
                      step="0.01"
                      type="number"
                      value={findingFilters.epssMin}
                    />
                    <span className="text-xs text-muted-foreground">to</span>
                    <Input
                      aria-label="EPSS max"
                      className="h-9 w-20 text-sm"
                      inputMode="decimal"
                      max="1"
                      min="0"
                      onChange={(e) =>
                        onFilterChange("epssMax", e.target.value)
                      }
                      placeholder="Max"
                      step="0.01"
                      type="number"
                      value={findingFilters.epssMax}
                    />
                  </div>
                </div>

                <div className="flex flex-col gap-1">
                  <span className="text-[11px] font-semibold uppercase text-muted-foreground">
                    CVSS
                  </span>
                  <div className="flex items-center gap-1">
                    <Input
                      aria-label="CVSS min"
                      className="h-9 w-20 text-sm"
                      inputMode="decimal"
                      max="10"
                      min="0"
                      onChange={(e) =>
                        onFilterChange("cvssMin", e.target.value)
                      }
                      placeholder="Min"
                      step="0.1"
                      type="number"
                      value={findingFilters.cvssMin}
                    />
                    <span className="text-xs text-muted-foreground">to</span>
                    <Input
                      aria-label="CVSS max"
                      className="h-9 w-20 text-sm"
                      inputMode="decimal"
                      max="10"
                      min="0"
                      onChange={(e) =>
                        onFilterChange("cvssMax", e.target.value)
                      }
                      placeholder="Max"
                      step="0.1"
                      type="number"
                      value={findingFilters.cvssMax}
                    />
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </VpwPanel>

        {/* ── States ───────────────────────────────────────────────── */}
        {hasError ? (
          <VpwStatusBanner title="Findings unavailable" tone="critical">
            {findingsError}
          </VpwStatusBanner>
        ) : null}
        {isLoading ? (
          <VpwPanel>
            <VpwSkeletonStack rows={6} />
          </VpwPanel>
        ) : null}

        {!isLoading && !hasError && !isDemo && projects.length === 0 ? (
          <VpwEmptyState
            action={
              <Button asChild>
                <Link to="/projects">Create a project</Link>
              </Button>
            }
            ariaLabel="No projects empty state"
            description="Create a project before reviewing findings."
            title="No projects yet"
          />
        ) : null}

        {!isLoading &&
        !hasError &&
        !isDemo &&
        selectedProject &&
        displayFindings.length === 0 &&
        !activeFindingFilters ? (
          <VpwEmptyState
            action={
              <Button asChild>
                <Link to="/imports">Import data</Link>
              </Button>
            }
            ariaLabel="No findings empty state"
            description="Import scanner, SBOM, or CVE-list data to create findings."
            title={`No findings in ${selectedProject.name}`}
          />
        ) : null}

        {!isLoading &&
        !hasError &&
        displayFindings.length === 0 &&
        activeFindingFilters ? (
          <VpwEmptyState
            action={
              <Button onClick={onClearFilters} type="button" variant="outline">
                Clear filters
              </Button>
            }
            ariaLabel="No filter matches"
            description="Try broadening the server-side query."
            title="No findings match these filters"
          />
        ) : null}

        {/* ── Table ────────────────────────────────────────────────── */}
        {displayFindings.length > 0 ? (
          <div className="flex flex-col gap-3">
            <section
              aria-label="Findings remediation queue"
              className="top-remediation-panel findings-queue-panel"
            >
              <div className="dashboard-panel-heading">
                <div>
                  <span>Remediation Focus</span>
                  <h3>Remediation Queue</h3>
                  <p>
                    {totalCount} prioritized finding
                    {totalCount === 1 ? "" : "s"} for{" "}
                    {displayProject?.name ?? "the selected project"}.
                  </p>
                </div>
                {!isDemo ? (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span>Rows</span>
                    <Select
                      onValueChange={(v) => onPageSizeChange(Number(v))}
                      value={String(findingPageSize)}
                    >
                      <SelectTrigger
                        aria-label="Rows"
                        className="h-8 w-16 text-xs"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {pageSizeOptions.map((s) => (
                          <SelectItem key={s} value={String(s)}>
                            {s}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                ) : null}
              </div>

              <FindingsDataTable
                findingDirection={findingDirection}
                findings={displayFindings}
                onOpenSheet={openSheet}
                onOpenWhy={openWhy}
                onSort={updateColumnSort}
                queueSort={queueSort}
              />
            </section>

            {/* Pagination */}
            {!isDemo ? (
              <div className="flex flex-wrap items-center justify-between gap-3 px-1">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span aria-live="polite">
                    Showing{" "}
                    <strong className="font-semibold text-foreground">
                      {pageStart}–{pageEnd}
                    </strong>{" "}
                    of{" "}
                    <strong className="font-semibold text-foreground">
                      {totalCount}
                    </strong>
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Button
                    className="h-7"
                    disabled={findingsLoading || findingOffset === 0}
                    onClick={onPagePrev}
                    size="sm"
                    type="button"
                    variant="outline"
                  >
                    <ChevronLeft
                      aria-hidden="true"
                      className="mr-1"
                      size={13}
                    />
                    Previous
                  </Button>
                  <Button
                    className="h-7"
                    disabled={
                      findingsLoading ||
                      findingOffset + findingPageSize >= findingCount
                    }
                    onClick={onPageNext}
                    size="sm"
                    type="button"
                    variant="outline"
                  >
                    Next
                    <ChevronRight
                      aria-hidden="true"
                      className="ml-1"
                      size={13}
                    />
                  </Button>
                </div>
              </div>
            ) : (
              <p className="text-xs text-center text-muted-foreground">
                Demo preview — {displayFindings.length} sample findings shown
              </p>
            )}
          </div>
        ) : null}

        {/* ── Dialogs ──────────────────────────────────────────────── */}
        <WhyDialog
          finding={whyFinding}
          onClose={() => setWhyOpen(false)}
          open={whyOpen}
        />
        <QuickViewSheet
          finding={sheetFinding}
          onClose={() => setSheetOpen(false)}
          open={sheetOpen}
        />
      </div>
    </TooltipProvider>
  )
}
