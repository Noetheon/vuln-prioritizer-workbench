import { Globe2, Link2, RefreshCw, Server, ShieldCheck } from "lucide-react"
import type { ReactNode } from "react"

import { MetricStrip, type MetricStripMetric } from "../vpw"
import type { AssetSummary } from "./asset-model"

export function AssetSummaryCards({
  assetSummary,
}: {
  assetSummary: AssetSummary
}) {
  const metrics: MetricStripMetric[] = [
    assetKpi({
      description: "Assets and target references in scope",
      icon: <Server aria-hidden="true" />,
      label: "Total assets",
      value: assetSummary.total,
    }),
    assetKpi({
      description: "External exposure",
      icon: <Globe2 aria-hidden="true" />,
      label: "Internet-facing",
      tone: "warning",
      value: assetSummary.internetFacing,
    }),
    assetKpi({
      description: "Critical or high context",
      icon: <ShieldCheck aria-hidden="true" />,
      label: "Critical services",
      tone: "critical",
      value: assetSummary.criticalServices,
    }),
    assetKpi({
      description: "Associated findings",
      icon: <Link2 aria-hidden="true" />,
      label: "Linked findings",
      tone: "info",
      value: assetSummary.linkedFindings,
    }),
    assetKpi({
      description: `${assetSummary.ownerCoverage}% owner coverage; ${assetSummary.production} production assets`,
      icon: <RefreshCw aria-hidden="true" />,
      label: "Rescore needed",
      tone: assetSummary.rescoreNeeded > 0 ? "warning" : "success",
      value: assetSummary.rescoreNeeded,
    }),
  ]

  return (
    <MetricStrip
      aria-label="Asset summary"
      className="assets-summary-strip"
      metrics={metrics}
      minCardWidth="11.75rem"
    />
  )
}

function assetKpi({
  description,
  icon,
  label,
  tone = "info",
  value,
}: {
  description: string
  icon: ReactNode
  label: string
  tone?: "success" | "warning" | "critical" | "info"
  value: ReactNode
}): MetricStripMetric {
  return { description, icon, label, tone, value }
}
