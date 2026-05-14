import { ChevronDown } from "lucide-react"
import { VpwPageContainer, VpwStatusBanner } from "@/components/vpw"
import {
  WaiverMetrics,
  WaiverRegister,
  WaiverReviewSection,
  WaiversHero,
} from "./WaiversWorkbenchSections"
import { WaiverDrawer } from "./WaiversWorkbenchDrawer"
import {
  evidenceCompleteness,
  isMissingApproval,
  reviewQueue,
  summaryValue,
  type WaiversWorkbenchProps,
} from "./waivers-workbench-model"

export type {
  WaiverDrawerMode,
  WaiverDebtSummaryItem,
  WaiverFormStateLike,
  WaiversWorkbenchProps,
} from "./waivers-workbench-model"

export function WaiversWorkbench(props: WaiversWorkbenchProps) {
  const activeWaivers = props.waivers.filter(
    (waiver) => waiver.status === "active",
  ).length
  const expiringSoon = summaryValue(props.waiverDebtSummary, "Expiring soon")
  const expired = summaryValue(props.waiverDebtSummary, "Expired")
  const reviewDue = summaryValue(props.waiverDebtSummary, "Review due")
  const acceptedFindings = summaryValue(
    props.waiverDebtSummary,
    "Accepted findings",
  )
  const missingApprovals = props.waivers.filter(isMissingApproval).length
  const completeness = evidenceCompleteness(props.waivers)
  const queue = reviewQueue(props.waiverDebtItems, props.waivers)

  return (
    <VpwPageContainer className="flex flex-col gap-8 px-0 py-0">
      <WaiversHero
        activeWaivers={activeWaivers}
        expired={expired}
        expiringSoon={expiringSoon}
        openWaiverDrawer={props.openWaiverDrawer}
        onProjectChange={props.onProjectChange}
        projectListLoading={props.projectListLoading}
        projectSummary={props.projectSummary}
        projects={props.projects}
        selectedProject={props.selectedProject}
        selectedProjectId={props.selectedProjectId}
      />

      {props.waiversError ? (
        <VpwStatusBanner title="Waivers unavailable" tone="critical">
          {props.waiversError}
        </VpwStatusBanner>
      ) : null}
      {props.waiverActionError ? (
        <VpwStatusBanner title="Waiver action failed" tone="critical">
          {props.waiverActionError}
        </VpwStatusBanner>
      ) : null}
      {props.waiverActionMessage ? (
        <VpwStatusBanner title="Waiver action complete" tone="success">
          {props.waiverActionMessage}
        </VpwStatusBanner>
      ) : null}

      <WaiverMetrics
        acceptedFindings={acceptedFindings}
        activeWaivers={activeWaivers}
        expired={expired}
        expiringSoon={expiringSoon}
        missingApprovals={missingApprovals}
        waiversLoading={props.waiversLoading}
      />
      <WaiverRegister
        openWaiverDrawer={props.openWaiverDrawer}
        onRefreshWaivers={props.onRefreshWaivers}
        selectedWaiverId={props.selectedWaiverId}
        selectedProjectId={props.selectedProjectId}
        waiverActionLoading={props.waiverActionLoading}
        waivers={props.waivers}
        waiversLoading={props.waiversLoading}
      />
      <details className="group rounded-[var(--vpw-radius-xl)] border border-[var(--vpw-border-default)] bg-[var(--vpw-bg-card)] shadow-[var(--vpw-shadow-0)]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 [&::-webkit-details-marker]:hidden">
          <span>
            <span className="vpw-label text-[var(--vpw-teal)]">
              Governance rollups
            </span>
            <span className="mt-1 block text-base font-semibold text-[var(--vpw-text-primary)]">
              Review queue and lifecycle context
            </span>
            <span className="mt-1 block text-sm text-[var(--vpw-text-secondary)]">
              {completeness}% evidence completeness across accepted-risk records.
            </span>
          </span>
          <ChevronDown
            aria-hidden="true"
            className="size-4 shrink-0 text-[var(--vpw-text-muted)] transition-transform group-open:rotate-180"
          />
        </summary>
        <div className="border-t border-[var(--vpw-border-subtle)] p-5">
          <WaiverReviewSection
            acceptedFindings={acceptedFindings}
            expired={expired}
            expiringSoon={expiringSoon}
            queue={queue}
            reviewDue={reviewDue}
          />
        </div>
      </details>
      <WaiverDrawer state={props} />
    </VpwPageContainer>
  )
}
