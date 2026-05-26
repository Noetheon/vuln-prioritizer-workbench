import type { FormEventHandler } from "react"
import type {
  FindingPublic,
  GovernanceWaiverDebtEntryPublic,
  ProjectDecisionSummaryPublic,
  ProjectPublic,
  WaiverPublic,
} from "@/api-client"

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

export type WaiverDrawerMode = "detail" | "create" | "review" | "expire" | null

export type WaiversWorkbenchProps = {
  projectListLoading: boolean
  projectSummary: ProjectDecisionSummaryPublic | null
  projects: ProjectPublic[]
  selectedProject: ProjectPublic | null
  selectedProjectId: string
  closeWaiverDrawer: () => void
  findings: FindingPublic[]
  findingsError: string
  findingsLoading: boolean
  onCreateWaiver: FormEventHandler<HTMLFormElement>
  onExpireWaiver: (waiver: WaiverPublic) => void
  onFieldChange: (field: keyof WaiverFormStateLike, value: string) => void
  onProjectChange: (projectId: string) => void
  onRefreshWaivers: () => void
  onReviewFieldChange: (field: keyof WaiverFormStateLike, value: string) => void
  onUpdateWaiver: FormEventHandler<HTMLFormElement>
  openWaiverDrawer: (mode: Exclude<WaiverDrawerMode, null>, waiver?: WaiverPublic) => void
  selectedWaiver: WaiverPublic | null
  selectedWaiverId: string
  waiverActionError: string
  waiverActionLoading: boolean
  waiverActionMessage: string
  waiverDebtItems: readonly GovernanceWaiverDebtEntryPublic[]
  waiverDebtSummary: readonly WaiverDebtSummaryItem[]
  waiverDrawerMode: WaiverDrawerMode
  waiverEditForm: WaiverFormStateLike
  waiverForm: WaiverFormStateLike
  waivers: WaiverPublic[]
  waiversError: string
  waiversLoading: boolean
}

export type WaiverMatchPreview = {
  description: string
  findings: FindingPublic[]
  severity: "neutral" | "success" | "warning"
  title: string
}

export type WaiverOwnerRollup = {
  acceptedFindings: number
  active: number
  owner: string
  reviewDue: number
}

export {
  evidenceFormComplete,
  scopeAnchorWarning,
  timeboxWarning,
  waiverFormFromRecord,
} from "./waiver-form-model"
export {
  daysLabel,
  evidenceDetail,
  evidenceStateLabel,
  evidenceStateToken,
  lifecycleLabel,
  lifecycleStatusToken,
  statusLabel,
  statusTone,
} from "./waiver-lifecycle-model"
export {
  debtScopeLabel,
  findingSummary,
  formatDate,
  joinedValues,
  matchingFindings,
  matchPreview,
  shortId,
  waiverScopeLabel,
  waiverScopeLines,
} from "./waiver-scope-model"
export {
  evidenceCompleteness,
  isMissingApproval,
  ownerRollups,
  reviewQueue,
  summaryValue,
  timelineItems,
} from "./waiver-summary-model"
