import type { MitigationLeverPublic } from "@/api-client"
import { DashboardMitigationLeverList } from "./DashboardMitigationLeverList"

export default function DashboardImpactChart({
  levers,
  totalOpenRiskScore = null,
}: {
  levers: readonly MitigationLeverPublic[]
  totalOpenRiskScore?: number | null
}) {
  return (
    <DashboardMitigationLeverList
      levers={levers}
      totalOpenRiskScore={totalOpenRiskScore}
    />
  )
}
