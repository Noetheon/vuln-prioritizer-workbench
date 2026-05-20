import { VpwPageContainer, VpwStatusBanner } from "@/components/vpw"
import {
  WaiverMetrics,
  WaiverRegister,
  WaiverReviewSection,
  WaiversHero,
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
  const expired = summaryValue(props.waiverDebtSummary, "Expired")
  const reviewDue = summaryValue(props.waiverDebtSummary, "Review due")
  const acceptedFindings = summaryValue(
    props.waiverDebtSummary,
    "Accepted findings",
  )
  const missingApprovals = props.waivers.filter(isMissingApproval).length
  const queue = reviewQueue(props.waiverDebtItems, props.waivers)

  return (
    <VpwPageContainer className="flex flex-col gap-8 px-0 py-0">
      <WaiversHero
        openWaiverDrawer={props.openWaiverDrawer}
        onProjectChange={props.onProjectChange}
        projectListLoading={props.projectListLoading}
        projectSummary={props.projectSummary}
        projects={props.projects}
        selectedProject={props.selectedProject}
        selectedProjectId={props.selectedProjectId}
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

      <WaiverMetrics
        acceptedFindings={acceptedFindings}
        activeWaivers={activeWaivers}
        expiringSoon={expiringSoon}
        missingApprovals={missingApprovals}
        reviewDue={reviewDue}
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
      <WaiverReviewSection
        acceptedFindings={acceptedFindings}
        expired={expired}
        expiringSoon={expiringSoon}
        missingApprovals={missingApprovals}
        queue={queue}
        reviewDue={reviewDue}
        waivers={props.waivers}
      />
      <WaiverDrawer state={props} />
    </VpwPageContainer>
  )
}
