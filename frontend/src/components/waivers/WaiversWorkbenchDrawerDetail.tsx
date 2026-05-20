import { Link } from "@/lib/router"
import { Clipboard, ExternalLink, Pencil, ShieldAlert } from "lucide-react"
import { useState } from "react"

import type { WaiverPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  CountBadge,
  RiskBadge,
  StatusLozenge,
  VpwGrid,
  VpwKeyValueList,
  VpwPanel,
  VpwSectionHeader,
  VpwStatusBanner,
  VpwToolbarGroup,
} from "@/components/vpw"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"
import {
  daysLabel,
  evidenceDetail,
  evidenceStateLabel,
  evidenceStateToken,
  findingSummary,
  formatDate,
  lifecycleLabel,
  lifecycleStatusToken,
  matchingFindings,
  statusLabel,
  type WaiversWorkbenchProps,
  waiverFormFromRecord,
  waiverScopeLabel,
  waiverScopeLines,
} from "./waivers-workbench-model"

export function WaiverDetailContent({
  findings,
  openWaiverDrawer,
  waiver,
  waiverActionLoading,
}: {
  findings: WaiversWorkbenchProps["findings"]
  openWaiverDrawer: WaiversWorkbenchProps["openWaiverDrawer"]
  waiver: WaiverPublic
  waiverActionLoading: boolean
}) {
  const [copyState, setCopyState] = useState("Copy Acceptance ID")
  const scope = waiverScopeLines(waiver)
  const matches = matchingFindings(waiverFormFromRecord(waiver), findings)
  const matchedCount = matches.length || waiver.matched_findings || 0
  const findingsSearch = {
    ...selectedProjectRouteSearch(waiver.project_id),
    q: waiver.cve_id ?? waiver.asset_key ?? waiver.service ?? "",
    status: "accepted",
  }

  async function copyAcceptanceId() {
    try {
      await navigator.clipboard.writeText(waiver.id)
      setCopyState("Acceptance ID copied")
      window.setTimeout(() => setCopyState("Copy Acceptance ID"), 1600)
    } catch {
      setCopyState("Copy failed")
      window.setTimeout(() => setCopyState("Copy Acceptance ID"), 1600)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          actions={
            <VpwToolbarGroup>
              <Button
                onClick={() => void copyAcceptanceId()}
                type="button"
                variant="outline"
              >
                <Clipboard aria-hidden="true" />
                {copyState}
              </Button>
              {waiver.status !== "expired" ? (
                <>
                  <Button
                    onClick={() => openWaiverDrawer("review", waiver)}
                    type="button"
                    variant="outline"
                  >
                    <Pencil aria-hidden="true" />
                    Review/edit
                  </Button>
                  <Button
                    aria-busy={waiverActionLoading}
                    disabled={waiverActionLoading}
                    onClick={() => openWaiverDrawer("expire", waiver)}
                    type="button"
                    variant="outline"
                  >
                    <ShieldAlert aria-hidden="true" />
                    Expire acceptance
                  </Button>
                </>
              ) : null}
            </VpwToolbarGroup>
          }
          description="Decision audit, lifecycle state, evidence, and current finding matches."
          eyebrow="Accepted risk decision"
          title={scope.primary}
        />
        <VpwKeyValueList
          columns={2}
          items={[
            {
              label: "State",
              value: (
                <StatusLozenge
                  label={lifecycleLabel(waiver)}
                  status={lifecycleStatusToken(waiver)}
                />
              ),
            },
            {
              label: "Evidence",
              value: (
                <StatusLozenge
                  label={evidenceStateLabel(waiver)}
                  status={evidenceStateToken(waiver)}
                />
              ),
              description: evidenceDetail(waiver),
            },
            {
              label: "Matched findings",
              value: (
                <Button asChild size="xs" variant="ghost">
                  <Link search={findingsSearch} to="/findings">
                    <CountBadge
                      label={`${matchedCount} finding${matchedCount === 1 ? "" : "s"}`}
                      value={matchedCount}
                    />
                  </Link>
                </Button>
              ),
            },
            {
              label: "Owner",
              value: waiver.owner,
              description: "Accountable owner",
            },
          ]}
        />
      </VpwPanel>

      <VpwStatusBanner title="Accepted risk stays visible" tone="info">
        Accepted risk remains visible in Triage and Finding Detail; it does not
        hide or delete evidence.
      </VpwStatusBanner>

      <VpwGrid columns={2}>
        <VpwPanel className="flex flex-col gap-4 p-5">
          <VpwSectionHeader
            eyebrow="Scope"
            title="Scope"
            description="Decision scope used to match affected findings."
          />
          <VpwKeyValueList
            density="compact"
            items={[
              { label: "Primary scope", value: scope.primary },
              {
                label: "Additional scope",
                value: scope.secondary || "No narrower scope recorded",
              },
              { label: "Acceptance ID", value: waiver.id },
            ]}
          />
        </VpwPanel>

        <VpwPanel className="flex flex-col gap-4 p-5">
          <VpwSectionHeader
            eyebrow="Decision"
            title="Decision"
            description="Owner rationale captured for audit review."
          />
          <VpwKeyValueList
            density="compact"
            items={[
              { label: "Owner", value: waiver.owner },
              { label: "Reason", value: waiver.reason },
            ]}
          />
        </VpwPanel>

        <VpwPanel className="flex flex-col gap-4 p-5">
          <VpwSectionHeader
            eyebrow="Timebox"
            title="Timebox"
            description="Review and expiry checkpoints for this decision."
          />
          <VpwKeyValueList
            density="compact"
            items={[
              {
                label: "Review date",
                value: formatDate(waiver.review_at),
              },
              {
                label: "Expiry",
                value: formatDate(waiver.expires_at),
                description: daysLabel(waiver.days_remaining),
              },
              {
                label: "Lifecycle",
                value: lifecycleLabel(waiver),
              },
            ]}
          />
        </VpwPanel>

        <VpwPanel className="flex flex-col gap-4 p-5">
          <VpwSectionHeader
            eyebrow="Evidence"
            title="Evidence"
            description="Approval evidence remains auditable after expiry."
          />
          <VpwKeyValueList
            density="compact"
            items={[
              {
                label: "Approval reference",
                value: waiver.approval_ref ?? "No approval reference",
              },
              {
                label: "Ticket URL",
                value: waiver.ticket_url ?? "No ticket URL",
              },
              {
                label: "Evidence state",
                value: evidenceStateLabel(waiver),
              },
            ]}
          />
        </VpwPanel>
      </VpwGrid>

      <VpwPanel className="flex flex-col gap-4 p-5">
        <VpwSectionHeader
          actions={
            <Button asChild variant="outline">
              <Link search={findingsSearch} to="/findings">
                <ExternalLink aria-hidden="true" />
                Open matched findings
              </Link>
            </Button>
          }
          description="Current findings that match this accepted-risk scope."
          eyebrow="Matched findings"
          title={`${matchedCount} affected finding${matchedCount === 1 ? "" : "s"}`}
        />
        {matches.length > 0 ? (
          <div className="grid gap-2">
            {matches.slice(0, 5).map((finding) => (
              <div
                className="grid gap-3 rounded-[var(--vpw-radius-lg)] border border-[var(--vpw-border-subtle)] bg-[var(--vpw-bg-card)] p-3 sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-center"
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
              </div>
            ))}
          </div>
        ) : (
          <VpwStatusBanner title="No current matches" tone="warning">
            No matching findings are currently loaded for {waiverScopeLabel(waiver)}.
            The historical decision record remains visible.
          </VpwStatusBanner>
        )}
      </VpwPanel>
    </div>
  )
}
