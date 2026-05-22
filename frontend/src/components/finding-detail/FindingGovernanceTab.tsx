import type { FindingDetailPublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import {
  StatusLozenge,
  VpwKeyValueList,
  VpwStatusBanner,
  VpwSurface,
  VpwSurfaceBody,
  VpwSurfaceDescription,
  VpwSurfaceHeader,
  VpwSurfaceTitle,
} from "@/components/vpw"
import { Link } from "@/lib/router"
import { formatLabel as labelize, optionalText } from "@/lib/ui-copy"
import type { FindingWaiverEvidence } from "@/lib/waiver-view"
import { selectedProjectRouteSearch } from "@/workbench/selected-project-search"

import type { FindingOccurrenceRow } from "./finding-detail-model"
import {
  findingOwnerDetailLabel,
  findingSlaLabel,
} from "./finding-detail-model"

export type FindingGovernanceTabProps = {
  finding: FindingDetailPublic
  occurrences: readonly FindingOccurrenceRow[]
  waiverEvidence: FindingWaiverEvidence | null
}

function findingVexStatus(
  finding: FindingDetailPublic,
  occurrences: readonly FindingOccurrenceRow[],
) {
  const occurrenceStatus = occurrences
    .map((occurrence) => String(occurrence.vex_status ?? "").trim())
    .find(Boolean)
  const occurrenceJustification = occurrences
    .map((occurrence) => String(occurrence.vex_justification ?? "").trim())
    .find(Boolean)

  if (finding.suppressed_by_vex) {
    return { hasVex: true, label: "Suppressed by VEX" }
  }
  if (occurrenceStatus) {
    return { hasVex: true, label: labelize(occurrenceStatus) }
  }
  if (occurrenceJustification) {
    return { hasVex: true, label: labelize(occurrenceJustification) }
  }
  return {
    hasVex: false,
    label: "No VEX overlay recorded for this finding.",
  }
}

export function FindingGovernanceTab({
  finding,
  occurrences,
  waiverEvidence,
}: FindingGovernanceTabProps) {
  const projectSearch = selectedProjectRouteSearch(finding.project_id)
  const acceptanceState = waiverEvidence
    ? `${optionalText(waiverEvidence.status)} · ${optionalText(
        waiverEvidence.reason,
      )}`
    : "No accepted risk record exists."
  const vexStatus = findingVexStatus(finding, occurrences)

  return (
    <section aria-label="Governance state" className="finding-governance-tab">
      <div className="finding-tab-intro">
        <span>Governance</span>
        <h3>SLA, ownership, acceptance, and review state</h3>
        <p>
          Governance context for defending the decision without changing the
          base CVSS, EPSS, KEV, or reviewed ATT&amp;CK priority signals.
        </p>
      </div>

      <VpwSurface className="finding-tab-card" aria-label="Governance summary">
        <VpwSurfaceHeader>
          <div className="finding-card-heading">
            <div>
              <VpwSurfaceDescription>Decision control</VpwSurfaceDescription>
              <VpwSurfaceTitle>Governance summary</VpwSurfaceTitle>
            </div>
            <StatusLozenge status={finding.status} />
          </div>
        </VpwSurfaceHeader>
        <VpwSurfaceBody className="finding-governance-grid">
          <VpwKeyValueList
            className="finding-decision-definition-list compact"
            columns={2}
            items={[
              {
                label: "SLA",
                value: findingSlaLabel(finding.priority),
              },
              {
                label: "Acceptance",
                value: acceptanceState,
              },
              {
                label: "Owner",
                value: findingOwnerDetailLabel(finding, occurrences),
              },
              {
                label: "Service",
                value: optionalText(finding.business_service),
              },
              {
                label: "Asset",
                value: optionalText(finding.asset_name ?? finding.asset_key),
              },
              {
                label: "Exposure",
                value: labelize(finding.exposure),
              },
              {
                label: "VEX",
                value: vexStatus.label,
              },
              {
                label: "Ticket / approval",
                value: optionalText(
                  waiverEvidence?.approvalRef ?? waiverEvidence?.ticketUrl,
                ),
              },
            ]}
          />
        </VpwSurfaceBody>
      </VpwSurface>

      {waiverEvidence ? (
        <VpwSurface className="finding-tab-card" aria-label="Risk acceptance">
          <VpwSurfaceHeader>
            <VpwSurfaceDescription>Accepted risk</VpwSurfaceDescription>
            <VpwSurfaceTitle>Recorded acceptance</VpwSurfaceTitle>
          </VpwSurfaceHeader>
          <VpwSurfaceBody>
            <VpwKeyValueList
              className="finding-decision-definition-list compact"
              columns={2}
              items={[
                {
                  label: "Owner",
                  value: optionalText(waiverEvidence.owner),
                },
                {
                  label: "Reason",
                  value: optionalText(waiverEvidence.reason),
                },
                {
                  label: "Expires",
                  value: optionalText(waiverEvidence.expiresOn),
                },
                {
                  label: "Review",
                  value: optionalText(waiverEvidence.reviewOn),
                },
                {
                  label: "Scope",
                  value: optionalText(
                    waiverEvidence.matchedScope ?? waiverEvidence.scope,
                  ),
                },
                {
                  label: "Approval",
                  value: optionalText(waiverEvidence.approvalRef),
                },
              ]}
            />
          </VpwSurfaceBody>
        </VpwSurface>
      ) : (
        <VpwStatusBanner
          className="finding-empty-panel"
          title="Risk acceptance"
          tone="info"
        >
          No accepted risk record exists. Use Risk acceptance when a documented
          exception is approved instead of remediation.
        </VpwStatusBanner>
      )}

      {!vexStatus.hasVex ? (
        <VpwStatusBanner
          className="finding-empty-panel"
          title="VEX overlay"
          tone="info"
        >
          No VEX overlay recorded for this finding.
        </VpwStatusBanner>
      ) : null}

      <div className="finding-governance-actions">
        <Button asChild size="sm" variant="outline">
          <Link search={projectSearch} to="/waivers">
            Risk acceptance
          </Link>
        </Button>
      </div>
    </section>
  )
}
