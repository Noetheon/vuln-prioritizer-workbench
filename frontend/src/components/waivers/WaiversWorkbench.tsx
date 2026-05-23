import "@/styles/waivers.css"

import { VpwPageContainer, VpwStatusBanner } from "@/components/vpw"
import {
  WaiverRegister,
  WaiverReviewSection,
  WaiversContext,
} from "./WaiversWorkbenchSections"
import { WaiverDrawer } from "./WaiversWorkbenchDrawer"
import {
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
  const reviewDue = summaryValue(props.waiverDebtSummary, "Review due")
  const acceptedFindings = summaryValue(
    props.waiverDebtSummary,
    "Accepted findings",
  )
  const missingApprovals = props.waivers.filter(isMissingApproval).length
  const queue = reviewQueue(props.waiverDebtItems, props.waivers)

  return (
    <VpwPageContainer className="waivers-workbench vpw-page-stack px-0 py-0">
      <WaiversContext
        acceptedFindings={acceptedFindings}
        activeWaivers={activeWaivers}
        expiringSoon={expiringSoon}
        missingApprovals={missingApprovals}
        openWaiverDrawer={props.openWaiverDrawer}
        projectListLoading={props.projectListLoading}
        projects={props.projects}
        reviewDue={reviewDue}
        selectedProjectId={props.selectedProjectId}
        waiversLoading={props.waiversLoading}
      />

      {props.waiversError ? (
        <VpwStatusBanner title="Risk Acceptance unavailable" tone="critical">
          {props.waiversError}
        </VpwStatusBanner>
      ) : null}
      {props.findingsError ? (
        <VpwStatusBanner title="Matched findings unavailable" tone="warning">
          {props.findingsError}
        </VpwStatusBanner>
      ) : null}
      {props.waiverActionError ? (
        <VpwStatusBanner title="Risk Acceptance action failed" tone="critical">
          {props.waiverActionError}
        </VpwStatusBanner>
      ) : null}
      {props.waiverActionMessage ? (
        <VpwStatusBanner title="Risk Acceptance action complete" tone="success">
          {props.waiverActionMessage}
        </VpwStatusBanner>
      ) : null}

      <WaiverRegister
        openWaiverDrawer={props.openWaiverDrawer}
        onProjectChange={props.onProjectChange}
        onRefreshWaivers={props.onRefreshWaivers}
        projectListLoading={props.projectListLoading}
        projects={props.projects}
        selectedWaiverId={props.selectedWaiverId}
        selectedProjectId={props.selectedProjectId}
        waiverActionLoading={props.waiverActionLoading}
        waivers={props.waivers}
        waiversLoading={props.waiversLoading}
      />
      <WaiverReviewSection queue={queue} waivers={props.waivers} />
      <WaiverDrawer state={props} />
    </VpwPageContainer>
  )
}
