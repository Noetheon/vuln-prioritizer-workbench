import { VpwPageContainer, VpwStatusBanner } from "@/components/vpw"
import {
  CreateWaiverSection,
  WaiverMetrics,
  WaiverRegister,
  WaiverReviewSection,
  WaiversHero,
} from "./WaiversWorkbenchSections"
import {
  evidenceCompleteness,
  isMissingApproval,
  reviewQueue,
  summaryValue,
  type WaiversWorkbenchProps,
} from "./waivers-workbench-model"

export type {
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
        onExpireWaiver={props.onExpireWaiver}
        onRefreshWaivers={props.onRefreshWaivers}
        selectedProjectId={props.selectedProjectId}
        waiverActionLoading={props.waiverActionLoading}
        waivers={props.waivers}
        waiversLoading={props.waiversLoading}
      />
      <CreateWaiverSection
        completeness={completeness}
        onCreateWaiver={props.onCreateWaiver}
        onFieldChange={props.onFieldChange}
        projectListLoading={props.projectListLoading}
        projectSummary={props.projectSummary}
        projects={props.projects}
        reviewDue={reviewDue}
        selectedProject={props.selectedProject}
        selectedProjectId={props.selectedProjectId}
        waiverActionLoading={props.waiverActionLoading}
        waiverForm={props.waiverForm}
      />
      <WaiverReviewSection
        acceptedFindings={acceptedFindings}
        expired={expired}
        expiringSoon={expiringSoon}
        queue={queue}
        reviewDue={reviewDue}
      />
    </VpwPageContainer>
  )
}
