import type {
  FindingDetailPublic,
  FindingExplanationPublic,
} from "@/api-client"

import type { FindingDecisionReason } from "./finding-detail-model"
import { WhyPriorityPanel } from "./WhyPriorityPanel"

export type FindingDecisionTabProps = {
  decisionReasons: readonly FindingDecisionReason[]
  explanation: FindingExplanationPublic | null
  finding: FindingDetailPublic
  reasonRows: readonly { detail: string; label: string }[]
}

export function FindingDecisionTab({
  decisionReasons,
  explanation,
  finding,
  reasonRows,
}: FindingDecisionTabProps) {
  return (
    <WhyPriorityPanel
      decisionReasons={decisionReasons}
      explanation={explanation}
      finding={finding}
      reasonRows={reasonRows}
    />
  )
}
