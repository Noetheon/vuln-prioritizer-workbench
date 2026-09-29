import type { FindingPublic } from "@/api-client"
import { VpwBadge } from "@/components/vpw"
import { slaDueSummary } from "@/lib/finding-sla-due"

export function SlaDueBadge({
  finding,
}: {
  finding: Pick<FindingPublic, "sla_due_at" | "sla_state">
}) {
  const due = slaDueSummary(finding)
  if (!due) return null
  return (
    <VpwBadge density="compact" title={due.title} tone={due.tone}>
      {due.label}
    </VpwBadge>
  )
}
