import { Link } from "@tanstack/react-router"
import {
  AlertTriangle,
  CalendarClock,
  ClipboardCheck,
  FileCheck2,
  RefreshCw,
  ShieldCheck,
} from "lucide-react"
import type { FormEventHandler } from "react"
import type {
  GovernanceWaiverDebtEntryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  WaiverPublic,
} from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import {
  VpwBadge,
  type VpwBadgeTone,
  VpwDataTable,
  type VpwDataTableColumn,
  VpwEmptyState,
  VpwField,
  VpwGrid,
  VpwKeyValueList,
  VpwMetricCard,
  VpwPageContainer,
  VpwPanel,
  VpwProgress,
  VpwSection,
  VpwSectionHeader,
  VpwSkeletonStack,
  VpwStatusBanner,
  VpwTimeline,
  type VpwTimelineItem,
  VpwToolbar,
  VpwToolbarGroup,
  VpwWaiverDecisionCard,
} from "@/components/vpw"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"

export type WaiverFormStateLike = {
  approvalRef: string
  assetId: string
  assetKey: string
  cveId: string
  expiresAt: string
  findingId: string
  owner: string
  reason: string
  reviewAt: string
  service: string
  ticketUrl: string
}

export type WaiverDebtSummaryItem = {
  detail: string
  label: string
  value: string
}

export type WaiversWorkbenchProps = {
  projectListLoading: boolean
  projectSummary: ProjectDecisionSummaryPublic | null
  projects: ProjectPublic[]
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  onCreateWaiver: FormEventHandler<HTMLFormElement>
  onExpireWaiver: (waiver: WaiverPublic) => void
  onFieldChange: (field: keyof WaiverFormStateLike, value: string) => void
  onProjectChange: (projectId: string) => void
  onRefreshWaivers: () => void
  waiverActionError: string
  waiverActionLoading: boolean
  waiverActionMessage: string
  waiverDebtItems: readonly GovernanceWaiverDebtEntryPublic[]
  waiverDebtSummary: readonly WaiverDebtSummaryItem[]
  waiverForm: WaiverFormStateLike
  waivers: WaiverPublic[]
  waiversError: string
  waiversLoading: boolean
}

function joinedValues(values: Array<string | null | undefined>) {
  const visible = values.filter(Boolean)
  return visible.length > 0 ? visible.join(" / ") : "Project scope"
}

function shortId(value: string | null | undefined) {
  return value ? value.slice(0, 8) : "N.A."
}

function formatDate(value: string | null | undefined) {
  if (!value) return "N.A."
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
  }).format(date)
}

function waiverScopeLabel(waiver: WaiverPublic) {
  return joinedValues([
    waiver.finding_id ? `Finding ${shortId(waiver.finding_id)}` : null,
    waiver.cve_id ? `CVE ${waiver.cve_id}` : null,
    waiver.asset_id ? `Asset ID ${shortId(waiver.asset_id)}` : null,
    waiver.asset_key ? `Asset ${waiver.asset_key}` : null,
    waiver.service ? `Service ${waiver.service}` : null,
  ])
}

function debtScopeLabel(item: GovernanceWaiverDebtEntryPublic) {
  return joinedValues([
    item.scope,
    item.cve_id ? `CVE ${item.cve_id}` : null,
    item.asset_key ? `Asset ${item.asset_key}` : null,
    item.service ? `Service ${item.service}` : null,
    item.finding_id ? `Finding ${shortId(item.finding_id)}` : null,
  ])
}

function statusTone(status: string | null | undefined): VpwBadgeTone {
  switch (status) {
    case "active":
      return "success"
    case "review_due":
      return "warning"
    case "expired":
      return "critical"
    default:
      return "neutral"
  }
}

function statusLabel(status: string | null | undefined) {
  return labelize(status ?? "unknown")
}

function daysLabel(days: number | null | undefined) {
  if (days === null || days === undefined) return "No lifecycle data"
  if (days < 0) return `${Math.abs(days)} day(s) overdue`
  if (days === 0) return "Due today"
  return `${days} day(s) remaining`
}

function summaryValue(
  summary: readonly WaiverDebtSummaryItem[],
  label: string,
  fallback = "0",
) {
  return summary.find((item) => item.label === label)?.value ?? fallback
}

function isMissingApproval(waiver: WaiverPublic) {
  return !waiver.approval_ref && !waiver.ticket_url
}

function evidenceCompleteness(waivers: readonly WaiverPublic[]) {
  if (waivers.length === 0) return 0
  const complete = waivers.filter((waiver) => !isMissingApproval(waiver)).length
  return Math.round((complete / waivers.length) * 100)
}

function reviewQueue(
  debtItems: readonly GovernanceWaiverDebtEntryPublic[],
  waivers: readonly WaiverPublic[],
) {
  if (debtItems.length > 0) {
    return debtItems
      .slice()
      .sort((left, right) => left.days_remaining - right.days_remaining)
      .slice(0, 4)
      .map((item) => ({
        id: item.id,
        owner: item.owner,
        reason: `${statusLabel(item.status)} waiver affecting ${item.matched_findings ?? 0} finding(s).`,
        reviewDate: item.review_at
          ? formatDate(item.review_at)
          : formatDate(item.expires_at),
        scope: debtScopeLabel(item),
        status: statusLabel(item.status),
        statusTone: statusTone(item.status),
      }))
  }

  return waivers
    .slice()
    .sort(
      (left, right) =>
        (left.days_remaining ?? 9999) - (right.days_remaining ?? 9999),
    )
    .slice(0, 4)
    .map((waiver) => ({
      id: waiver.id,
      owner: waiver.owner,
      reason: waiver.reason,
      reviewDate: waiver.review_at
        ? formatDate(waiver.review_at)
        : formatDate(waiver.expires_at),
      scope: waiverScopeLabel(waiver),
      status: statusLabel(waiver.status),
      statusTone: statusTone(waiver.status),
    }))
}

function timelineItems({
  acceptedFindings,
  expired,
  expiringSoon,
  reviewDue,
}: {
  acceptedFindings: string
  expired: string
  expiringSoon: string
  reviewDue: string
}): VpwTimelineItem[] {
  return [
    {
      title: "Created",
      description:
        "Risk acceptance starts only after scope, owner, reason and expiry are recorded.",
      meta: "Required",
      tone: "success",
    },
    {
      title: "Approved",
      description:
        "Approval references or ticket URLs make accepted risk auditable in reports.",
      meta: `${acceptedFindings} accepted finding(s)`,
      tone: "success",
    },
    {
      title: "Review due",
      description:
        "Owner review keeps accepted risk visible before it becomes stale.",
      meta: `${reviewDue} due`,
      tone: Number(reviewDue) > 0 ? "warning" : "neutral",
    },
    {
      title: "Expiring",
      description:
        "Waivers close to expiry should be remediated, renewed, or explicitly re-approved.",
      meta: `${expiringSoon} soon`,
      tone: Number(expiringSoon) > 0 ? "warning" : "neutral",
    },
    {
      title: "Expired",
      description:
        "Expired accepted risk should return to normal remediation pressure.",
      meta: `${expired} expired`,
      tone: Number(expired) > 0 ? "critical" : "neutral",
    },
  ]
}

export function WaiversWorkbench({
  onCreateWaiver,
  onExpireWaiver,
  onFieldChange,
  onProjectChange,
  onRefreshWaivers,
  projectListLoading,
  projectSummary,
  projects,
  selectedProject,
  selectedProjectId,
  waiverActionError,
  waiverActionLoading,
  waiverActionMessage,
  waiverDebtItems,
  waiverDebtSummary,
  waiverForm,
  waivers,
  waiversError,
  waiversLoading,
}: WaiversWorkbenchProps) {
  const activeWaivers = waivers.filter(
    (waiver) => waiver.status === "active",
  ).length
  const expiringSoon = summaryValue(waiverDebtSummary, "Expiring soon")
  const expired = summaryValue(waiverDebtSummary, "Expired")
  const reviewDue = summaryValue(waiverDebtSummary, "Review due")
  const acceptedFindings = summaryValue(waiverDebtSummary, "Accepted findings")
  const missingApprovals = waivers.filter(isMissingApproval).length
  const completeness = evidenceCompleteness(waivers)
  const queue = reviewQueue(waiverDebtItems, waivers)

  const columns: VpwDataTableColumn<WaiverPublic>[] = [
    {
      id: "finding",
      header: "Finding / CVE",
      className: "w-[12%] break-words",
      headerClassName: "w-[12%]",
      cell: (waiver) => (
        <div>
          <strong className="block text-sm text-[var(--vpw-text-primary)]">
            {waiver.cve_id ?? "Scoped waiver"}
          </strong>
          <span className="font-mono text-xs text-[var(--vpw-text-muted)]">
            {waiver.finding_id
              ? `Finding ${shortId(waiver.finding_id)}`
              : `Waiver ${shortId(waiver.id)}`}
          </span>
        </div>
      ),
    },
    {
      id: "scope",
      header: "Scope",
      className: "w-[12%] break-words",
      headerClassName: "w-[12%]",
      cell: (waiver) => waiverScopeLabel(waiver),
    },
    {
      id: "owner",
      header: "Owner",
      className: "w-[9%] break-words",
      headerClassName: "w-[9%]",
      cell: (waiver) => waiver.owner,
    },
    {
      id: "reason",
      header: "Reason",
      className: "w-[14%]",
      headerClassName: "w-[14%]",
      cell: (waiver) => (
        <span className="line-clamp-2 text-sm leading-5">{waiver.reason}</span>
      ),
    },
    {
      id: "status",
      header: "Status",
      className: "w-[9%]",
      headerClassName: "w-[9%]",
      cell: (waiver) => (
        <VpwBadge tone={statusTone(waiver.status)}>
          {statusLabel(waiver.status)}
        </VpwBadge>
      ),
    },
    {
      id: "expires",
      header: "Expires",
      className: "w-[11%]",
      headerClassName: "w-[11%]",
      cell: (waiver) => (
        <div>
          <span>{formatDate(waiver.expires_at)}</span>
          <small className="block text-xs text-[var(--vpw-text-muted)]">
            {daysLabel(waiver.days_remaining)}
          </small>
        </div>
      ),
    },
    {
      id: "review",
      header: "Review date",
      className: "w-[10%]",
      headerClassName: "w-[10%]",
      cell: (waiver) => formatDate(waiver.review_at),
    },
    {
      id: "approval",
      header: "Approval reference",
      className: "w-[13%] break-words",
      headerClassName: "w-[13%]",
      cell: (waiver) => optionalText(waiver.approval_ref ?? waiver.ticket_url),
    },
    {
      id: "actions",
      header: "Actions",
      className: "w-[10%]",
      headerClassName: "w-[10%]",
      cell: (waiver) => (
        <div className="flex flex-wrap gap-2">
          {waiver.finding_id ? (
            <Button asChild size="sm" variant="outline">
              <Link
                to="/findings/$findingId"
                params={{ findingId: waiver.finding_id }}
              >
                View finding
              </Link>
            </Button>
          ) : null}
          {waiver.status !== "expired" ? (
            <Button
              disabled={waiverActionLoading}
              onClick={() => onExpireWaiver(waiver)}
              size="sm"
              type="button"
              variant="outline"
            >
              Expire
            </Button>
          ) : null}
        </div>
      ),
    },
  ]

  return (
    <VpwPageContainer className="space-y-8 px-0 py-0">
      <VpwSection>
        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            actions={
              <>
                <Button asChild>
                  <a href="#create-waiver">Create waiver</a>
                </Button>
                <Button asChild variant="outline">
                  <Link to="/findings">View findings</Link>
                </Button>
              </>
            }
            description="Govern accepted risk decisions with owner, scope, expiry and evidence."
            eyebrow="Risk acceptance"
            title="Waivers"
          />
          <VpwToolbar label="Waiver context">
            <VpwToolbarGroup className="min-w-0">
              <VpwField className="min-w-64" label="Project">
                <Select
                  disabled={projectListLoading || projects.length === 0}
                  onValueChange={onProjectChange}
                  value={selectedProjectId}
                >
                  <SelectTrigger aria-label="Waivers project">
                    <SelectValue placeholder="Select project" />
                  </SelectTrigger>
                  <SelectContent>
                    {projects.length === 0 ? (
                      <SelectItem disabled value="none">
                        No projects
                      </SelectItem>
                    ) : null}
                    {projects.map((project) => (
                      <SelectItem key={project.id} value={project.id}>
                        {project.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </VpwField>
            </VpwToolbarGroup>
            <VpwToolbarGroup>
              <VpwBadge tone={selectedProject ? "success" : "warning"}>
                Active project: {selectedProject?.name ?? "None"}
              </VpwBadge>
              <VpwBadge tone="info">Active: {activeWaivers}</VpwBadge>
              <VpwBadge tone={Number(expiringSoon) > 0 ? "warning" : "neutral"}>
                Expiring soon: {expiringSoon}
              </VpwBadge>
              <VpwBadge tone={Number(expired) > 0 ? "critical" : "neutral"}>
                Expired: {expired}
              </VpwBadge>
              <VpwBadge
                tone={projectSummary?.latest_run_id ? "success" : "neutral"}
              >
                Evidence {projectSummary?.latest_run_id ? "ready" : "pending"}
              </VpwBadge>
            </VpwToolbarGroup>
          </VpwToolbar>
        </VpwPanel>
      </VpwSection>

      {waiversError ? (
        <VpwStatusBanner title="Waivers unavailable" tone="critical">
          {waiversError}
        </VpwStatusBanner>
      ) : null}
      {waiverActionError ? (
        <VpwStatusBanner title="Waiver action failed" tone="critical">
          {waiverActionError}
        </VpwStatusBanner>
      ) : null}
      {waiverActionMessage ? (
        <VpwStatusBanner title="Waiver action complete" tone="success">
          {waiverActionMessage}
        </VpwStatusBanner>
      ) : null}

      <VpwGrid columns={1} className="md:grid-cols-2 xl:grid-cols-5">
        <VpwMetricCard
          description="currently accepted risk"
          icon={<ShieldCheck aria-hidden="true" className="h-4 w-4" />}
          label="Active waivers"
          tone="success"
          value={waiversLoading ? "Loading" : activeWaivers}
        />
        <VpwMetricCard
          description="within the review window"
          icon={<CalendarClock aria-hidden="true" className="h-4 w-4" />}
          label="Expiring soon"
          tone={Number(expiringSoon) > 0 ? "warning" : "neutral"}
          value={expiringSoon}
        />
        <VpwMetricCard
          description="past expiry date"
          icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}
          label="Expired waivers"
          tone={Number(expired) > 0 ? "critical" : "neutral"}
          value={expired}
        />
        <VpwMetricCard
          description="findings currently accepted"
          icon={<FileCheck2 aria-hidden="true" className="h-4 w-4" />}
          label="Accepted findings"
          tone="info"
          value={acceptedFindings}
        />
        <VpwMetricCard
          description="missing approval reference or ticket"
          icon={<ClipboardCheck aria-hidden="true" className="h-4 w-4" />}
          label="Incomplete evidence"
          tone={missingApprovals > 0 ? "warning" : "success"}
          value={waiversLoading ? "Loading" : missingApprovals}
        />
      </VpwGrid>

      <VpwGrid columns={2}>
        <div id="create-waiver">
          <VpwPanel className="space-y-5 p-5">
            <VpwSectionHeader
              description="Create an accepted-risk decision only when remediation cannot happen immediately."
              eyebrow="Governance form"
              title="Create waiver"
            />
            <form className="space-y-5" onSubmit={onCreateWaiver}>
              <VpwGrid columns={2}>
                <VpwField htmlFor="waiver-cve-id" label="CVE ID">
                  <Input
                    aria-label="Waiver CVE ID"
                    id="waiver-cve-id"
                    onChange={(event) =>
                      onFieldChange("cveId", event.target.value)
                    }
                    placeholder="CVE-2024-3094"
                    value={waiverForm.cveId}
                  />
                </VpwField>
                <VpwField htmlFor="waiver-finding-id" label="Finding ID">
                  <Input
                    aria-label="Waiver finding ID"
                    id="waiver-finding-id"
                    onChange={(event) =>
                      onFieldChange("findingId", event.target.value)
                    }
                    placeholder="Optional UUID"
                    value={waiverForm.findingId}
                  />
                </VpwField>
                <VpwField htmlFor="waiver-asset-key" label="Asset key">
                  <Input
                    aria-label="Waiver asset key"
                    id="waiver-asset-key"
                    onChange={(event) =>
                      onFieldChange("assetKey", event.target.value)
                    }
                    placeholder="payments-api"
                    value={waiverForm.assetKey}
                  />
                </VpwField>
                <VpwField htmlFor="waiver-service" label="Service">
                  <Input
                    aria-label="Waiver service"
                    id="waiver-service"
                    onChange={(event) =>
                      onFieldChange("service", event.target.value)
                    }
                    placeholder="checkout"
                    value={waiverForm.service}
                  />
                </VpwField>
                <VpwField htmlFor="waiver-asset-id" label="Asset ID">
                  <Input
                    aria-label="Waiver asset ID"
                    id="waiver-asset-id"
                    onChange={(event) =>
                      onFieldChange("assetId", event.target.value)
                    }
                    placeholder="Optional UUID"
                    value={waiverForm.assetId}
                  />
                </VpwField>
                <VpwField htmlFor="waiver-owner" label="Owner" required>
                  <Input
                    aria-label="Waiver owner"
                    id="waiver-owner"
                    onChange={(event) =>
                      onFieldChange("owner", event.target.value)
                    }
                    placeholder="risk-owner"
                    value={waiverForm.owner}
                  />
                </VpwField>
                <VpwField
                  className="lg:col-span-2"
                  htmlFor="waiver-reason"
                  label="Reason"
                  required
                >
                  <Textarea
                    aria-label="Waiver reason"
                    id="waiver-reason"
                    onChange={(event) =>
                      onFieldChange("reason", event.target.value)
                    }
                    rows={3}
                    value={waiverForm.reason}
                  />
                </VpwField>
                <VpwField
                  htmlFor="waiver-expires-at"
                  label="Expiry date"
                  required
                >
                  <Input
                    aria-label="Waiver expires at"
                    id="waiver-expires-at"
                    onChange={(event) =>
                      onFieldChange("expiresAt", event.target.value)
                    }
                    type="date"
                    value={waiverForm.expiresAt}
                  />
                </VpwField>
                <VpwField htmlFor="waiver-review-at" label="Review date">
                  <Input
                    aria-label="Waiver review at"
                    id="waiver-review-at"
                    onChange={(event) =>
                      onFieldChange("reviewAt", event.target.value)
                    }
                    type="date"
                    value={waiverForm.reviewAt}
                  />
                </VpwField>
                <VpwField
                  htmlFor="waiver-approval-ref"
                  label="Approval reference"
                >
                  <Input
                    aria-label="Waiver approval reference"
                    id="waiver-approval-ref"
                    onChange={(event) =>
                      onFieldChange("approvalRef", event.target.value)
                    }
                    placeholder="CAB-064"
                    value={waiverForm.approvalRef}
                  />
                </VpwField>
                <VpwField htmlFor="waiver-ticket-url" label="Ticket URL">
                  <Input
                    aria-label="Waiver ticket URL"
                    id="waiver-ticket-url"
                    onChange={(event) =>
                      onFieldChange("ticketUrl", event.target.value)
                    }
                    placeholder="https://tracker.example/..."
                    value={waiverForm.ticketUrl}
                  />
                </VpwField>
              </VpwGrid>
              <div className="flex flex-wrap gap-2">
                <Button
                  disabled={
                    waiverActionLoading ||
                    projectListLoading ||
                    projects.length === 0
                  }
                  type="submit"
                >
                  {waiverActionLoading ? "Creating" : "Create waiver"}
                </Button>
                <Button asChild type="button" variant="outline">
                  <Link to="/findings">View findings</Link>
                </Button>
              </div>
            </form>
          </VpwPanel>
        </div>

        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            description="Accepted risk remains visible in prioritization and evidence."
            eyebrow="Safety rules"
            title="Governance guidance"
          />
          <VpwStatusBanner
            title="Owner, reason and expiry are required"
            tone="warning"
          >
            Waivers should document why risk is accepted and when it must be
            revisited.
          </VpwStatusBanner>
          <VpwStatusBanner title="Accepted risk stays visible" tone="info">
            Reports should continue to show accepted findings instead of hiding
            them silently.
          </VpwStatusBanner>
          <VpwStatusBanner
            title="Critical findings still need review"
            tone="critical"
          >
            A waiver is an explicit decision record, not a remediation
            replacement.
          </VpwStatusBanner>
          <VpwKeyValueList
            columns={2}
            items={[
              {
                label: "Active project",
                value: selectedProject?.name ?? "No project",
              },
              {
                label: "Latest run",
                value: projectSummary?.latest_run_id
                  ? shortId(projectSummary.latest_run_id)
                  : "No run yet",
              },
              {
                label: "Evidence completeness",
                value: `${completeness}%`,
                tone: completeness >= 80 ? "success" : "warning",
              },
              {
                label: "Review due",
                value: reviewDue,
                tone: Number(reviewDue) > 0 ? "warning" : "neutral",
              },
            ]}
          />
          <VpwProgress
            label="Approval evidence coverage"
            tone={completeness >= 80 ? "success" : "warning"}
            value={completeness}
          />
        </VpwPanel>
      </VpwGrid>

      <VpwSection>
        <VpwSectionHeader
          actions={
            <Button
              onClick={onRefreshWaivers}
              size="sm"
              type="button"
              variant="outline"
            >
              <RefreshCw aria-hidden="true" className="h-4 w-4" />
              Refresh
            </Button>
          }
          description="Accepted risk remains visible after creation and expiry."
          eyebrow="Register"
          title="Risk acceptance register"
        />
        {waiversLoading ? (
          <VpwPanel className="p-5">
            <VpwSkeletonStack rows={5} />
          </VpwPanel>
        ) : (
          <VpwDataTable
            caption="Waivers table"
            className="[&_table]:table-fixed [&_td]:px-3 [&_th]:whitespace-normal [&_th]:px-3"
            columns={columns}
            data={waivers}
            density="compact"
            emptyState={
              <VpwEmptyState
                action={
                  <div className="flex flex-wrap justify-center gap-2">
                    <Button asChild>
                      <a href="#create-waiver">Create waiver</a>
                    </Button>
                    <Button asChild variant="outline">
                      <Link to="/findings">View findings</Link>
                    </Button>
                  </div>
                }
                description="Create a waiver only when remediation cannot happen immediately and compensating controls are documented."
                title="No accepted risk decisions yet"
              />
            }
            getRowKey={(waiver) => waiver.id}
          />
        )}
      </VpwSection>

      <VpwGrid columns={2}>
        <VpwPanel className="space-y-5 p-5">
          <VpwSectionHeader
            description="Lifecycle checkpoints for accepted risk decisions."
            eyebrow="Review workflow"
            title="Governance timeline"
          />
          <VpwTimeline
            items={timelineItems({
              acceptedFindings,
              expired,
              expiringSoon,
              reviewDue,
            })}
          />
        </VpwPanel>

        <VpwSection>
          <VpwSectionHeader
            description="Waivers nearest review or expiry."
            eyebrow="Review queue"
            title="Owner follow-up"
          />
          {queue.length === 0 ? (
            <VpwPanel>
              <VpwEmptyState
                description="No waiver lifecycle debt is currently recorded for this project."
                title="No review queue"
              />
            </VpwPanel>
          ) : (
            <div className="grid gap-4">
              {queue.map((item) => (
                <VpwWaiverDecisionCard
                  key={item.id}
                  owner={item.owner}
                  reason={`${item.scope}. ${item.reason}`}
                  reviewDate={item.reviewDate}
                  status={item.status}
                  statusTone={item.statusTone}
                />
              ))}
            </div>
          )}
        </VpwSection>
      </VpwGrid>
    </VpwPageContainer>
  )
}
