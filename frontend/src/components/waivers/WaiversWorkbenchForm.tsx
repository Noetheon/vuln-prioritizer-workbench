import { Link } from "@/lib/router"
import { AlertTriangle, CheckCircle2, Clock3 } from "lucide-react"

import type { AssetPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  CountBadge,
  RiskBadge,
  StatusLozenge,
  VpwField,
  VpwGrid,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  evidenceFormComplete,
  findingSummary,
  matchPreview,
  scopeAnchorWarning,
  statusLabel,
  timeboxWarning,
  type WaiversWorkbenchProps,
} from "./waivers-workbench-model"
import {
  type AcceptableFinding,
  findingScopeOptionLabel,
} from "./waiver-scope-model"
import { WaiverScopeFields } from "./WaiversWorkbenchScopeFields"

export function WaiverForm({
  assets = [],
  buttonLabel,
  findings,
  findingsLoading,
  fixedFindings,
  onCancel,
  onFieldChange,
  onSubmit,
  waiverActionLoading,
  waiverForm,
}: {
  assets?: readonly AssetPublic[]
  buttonLabel: string
  findings: WaiversWorkbenchProps["findings"]
  findingsLoading: boolean
  // Accepts exactly these findings, one acceptance each, instead of a scope.
  fixedFindings?: readonly AcceptableFinding[]
  onCancel?: () => void
  onFieldChange: WaiversWorkbenchProps["onFieldChange"]
  onSubmit: WaiversWorkbenchProps["onCreateWaiver"]
  waiverActionLoading: boolean
  waiverForm: WaiversWorkbenchProps["waiverForm"]
}) {
  const preview = matchPreview(waiverForm, findings, findingsLoading)
  const scopeWarning = fixedFindings ? "" : scopeAnchorWarning(waiverForm)
  const timeWarning = timeboxWarning(waiverForm)
  const hasEvidence = evidenceFormComplete(waiverForm)

  return (
    <form className="flex flex-col gap-5" onSubmit={onSubmit}>
      <VpwPanel className="flex flex-col gap-4 p-4">
        <VpwSectionHeader
          description={
            fixedFindings
              ? "Each finding gets its own acceptance with the decision below."
              : "Anchor the decision to the narrowest scope that matches the accepted risk."
          }
          eyebrow="Scope"
          title={
            fixedFindings
              ? `${fixedFindings.length} finding${fixedFindings.length === 1 ? "" : "s"}`
              : "Scope"
          }
        />
        {fixedFindings ? (
          <FixedFindingsScope findings={fixedFindings} />
        ) : (
          <WaiverScopeFields
            assets={assets}
            findings={findings}
            onFieldChange={onFieldChange}
            waiverForm={waiverForm}
          />
        )}
        {scopeWarning ? (
          <VpwStatusBanner title="Scope is broad" tone="warning">
            {scopeWarning}
          </VpwStatusBanner>
        ) : null}
      </VpwPanel>

      <VpwPanel className="flex flex-col gap-4 p-4">
        <VpwSectionHeader
          description="Capture the accountable owner and the reason this risk is accepted."
          eyebrow="Decision"
          title="Decision owner and rationale"
        />
        <VpwGrid columns={2}>
          <VpwField htmlFor="waiver-owner" label="Owner" required>
            <Input
              aria-label="Acceptance owner"
              id="waiver-owner"
              onChange={(event) => onFieldChange("owner", event.target.value)}
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
              aria-label="Acceptance reason"
              id="waiver-reason"
              onChange={(event) => onFieldChange("reason", event.target.value)}
              placeholder="Why the risk is accepted, which controls are in place, and when this will be revisited."
              rows={4}
              value={waiverForm.reason}
            />
          </VpwField>
        </VpwGrid>
      </VpwPanel>

      <VpwPanel className="flex flex-col gap-4 p-4">
        <VpwSectionHeader
          description="Accepted risk must be time-boxed and reviewed before it expires."
          eyebrow="Timebox"
          title="Timebox"
        />
        <VpwGrid columns={2}>
          <VpwField htmlFor="waiver-review-at" label="Review date">
            <Input
              aria-label="Acceptance review at"
              id="waiver-review-at"
              onChange={(event) =>
                onFieldChange("reviewAt", event.target.value)
              }
              type="date"
              value={waiverForm.reviewAt}
            />
          </VpwField>
          <VpwField htmlFor="waiver-expires-at" label="Expiry date" required>
            <Input
              aria-label="Acceptance expires at"
              id="waiver-expires-at"
              onChange={(event) =>
                onFieldChange("expiresAt", event.target.value)
              }
              type="date"
              value={waiverForm.expiresAt}
            />
          </VpwField>
        </VpwGrid>
        {timeWarning ? (
          <VpwStatusBanner title="Timebox needs review" tone="warning">
            <span className="inline-flex items-start gap-2">
              <Clock3 aria-hidden="true" className="mt-0.5 size-4" />
              {timeWarning}
            </span>
          </VpwStatusBanner>
        ) : null}
      </VpwPanel>

      <VpwPanel className="flex flex-col gap-4 p-4">
        <VpwSectionHeader
          description="Evidence is complete when an approval reference or ticket URL is recorded."
          eyebrow="Evidence"
          title="Evidence and approval"
        />
        <VpwGrid columns={2}>
          <VpwField htmlFor="waiver-approval-ref" label="Approval reference">
            <Input
              aria-label="Acceptance approval reference"
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
              aria-label="Acceptance ticket URL"
              id="waiver-ticket-url"
              onChange={(event) =>
                onFieldChange("ticketUrl", event.target.value)
              }
              placeholder="https://tracker.example/..."
              value={waiverForm.ticketUrl}
            />
          </VpwField>
        </VpwGrid>
        <VpwStatusBanner
          title={hasEvidence ? "Evidence complete" : "Evidence incomplete"}
          tone={hasEvidence ? "success" : "warning"}
        >
          <span className="inline-flex items-start gap-2">
            {hasEvidence ? (
              <CheckCircle2 aria-hidden="true" className="mt-0.5 size-4" />
            ) : (
              <AlertTriangle aria-hidden="true" className="mt-0.5 size-4" />
            )}
            {hasEvidence
              ? "This decision has approval evidence for audit review."
              : "Add an approval reference or ticket URL before relying on this decision in governance evidence."}
          </span>
        </VpwStatusBanner>
      </VpwPanel>

      {fixedFindings ? null : (
        <VpwPanel className="flex flex-col gap-4 p-4">
          <VpwSectionHeader
            description={preview.description}
            eyebrow="Match preview"
            title={preview.title}
          />
          {preview.findings.length > 0 ? (
            <div className="grid gap-2">
              {preview.findings.slice(0, 4).map((finding) => (
                <div
                  className="grid gap-3 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-3 sm:grid-cols-[minmax(0,1fr)_auto_auto_auto] sm:items-center"
                  key={finding.id}
                >
                  <div className="min-w-0">
                    <Link
                      className="font-medium text-[var(--vpw-text-primary)] underline-offset-4 hover:underline"
                      params={{ findingId: finding.id }}
                      search={selectedProjectRouteSearch(finding.project_id)}
                      to="/findings/$findingId"
                    >
                      {findingSummary(finding)}
                    </Link>
                    <p className="mt-1 text-xs text-[var(--vpw-text-muted)]">
                      Owner {finding.owner ?? "Unassigned"}
                    </p>
                  </div>
                  <RiskBadge density="compact" level={finding.priority} />
                  <StatusLozenge
                    density="compact"
                    label={statusLabel(finding.status)}
                    status={finding.status}
                  />
                  <CountBadge label="Risk score" value={finding.risk_score ?? 0} />
                </div>
              ))}
              {preview.findings.length > 4 ? (
                <p className="text-sm text-[var(--vpw-text-secondary)]">
                  {preview.findings.length - 4} more matching findings are not
                  shown in this preview.
                </p>
              ) : null}
            </div>
          ) : (
            <VpwStatusBanner
              title={preview.title}
              tone={preview.severity === "warning" ? "warning" : "info"}
            >
              {preview.description}
            </VpwStatusBanner>
          )}
        </VpwPanel>
      )}

      <div className="sticky bottom-0 -mx-6 -mb-6 flex flex-wrap justify-end gap-2 border-t border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-page)] px-6 py-4">
        {onCancel ? (
          <Button
            disabled={waiverActionLoading}
            onClick={onCancel}
            type="button"
            variant="outline"
          >
            Cancel
          </Button>
        ) : null}
        <Button
          aria-busy={waiverActionLoading}
          disabled={waiverActionLoading}
          type="submit"
        >
          {waiverActionLoading ? "Saving" : buttonLabel}
        </Button>
      </div>
    </form>
  )
}

function FixedFindingsScope({
  findings,
}: {
  findings: readonly AcceptableFinding[]
}) {
  return (
    <ul aria-label="Findings to accept" className="grid gap-2">
      {findings.map((finding) => (
        <li
          className="flex min-w-0 flex-wrap items-center justify-between gap-2 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] px-3 py-2"
          key={finding.id}
        >
          <span className="min-w-0 text-sm text-[var(--vpw-text-primary)]">
            {findingScopeOptionLabel(finding)}
          </span>
          <RiskBadge density="compact" level={finding.priority} />
        </li>
      ))}
    </ul>
  )
}
